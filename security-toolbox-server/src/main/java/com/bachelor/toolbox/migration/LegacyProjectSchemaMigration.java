package com.bachelor.toolbox.migration;

import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import javax.sql.DataSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Repairs the pre-project schema without wiping unrelated application data.
 *
 * <p>Legacy task/schedule rows are retained only when their target maps to exactly one existing
 * project. Ambiguous or unassociated rows are removed, as they cannot satisfy the current
 * authorization model. The migration is idempotent and executes before Hibernate.
 */
public final class LegacyProjectSchemaMigration {
  private static final Logger log = LoggerFactory.getLogger(LegacyProjectSchemaMigration.class);
  private static final String TASKS = "security_tasks";
  private static final String SCHEDULES = "scan_schedules";

  private final DataSource dataSource;

  public LegacyProjectSchemaMigration(DataSource dataSource) {
    this.dataSource = dataSource;
  }

  private static final int MAX_OPEN_ATTEMPTS = 5;
  private static final long OPEN_RETRY_BASE_DELAY_MS = 500L;

  public void migrate() {
    // The migration is idempotent, so it is safe to retry when the database file cannot be
    // opened yet (e.g. a just-terminated backend still releasing the H2 file lock). Only the
    // connection-acquisition phase is retried; once a transaction runs, failures stay fatal.
    SQLException lastOpenFailure = null;
    for (int attempt = 1; attempt <= MAX_OPEN_ATTEMPTS; attempt++) {
      try (Connection connection = dataSource.getConnection()) {
        runMigration(connection);
        return;
      } catch (SQLException ex) {
        if (!isTransientOpenFailure(ex) || attempt == MAX_OPEN_ATTEMPTS) {
          throw new IllegalStateException("旧数据项目字段迁移失败，已停止启动以避免使用不完整授权数据", ex);
        }
        lastOpenFailure = ex;
        long delay = OPEN_RETRY_BASE_DELAY_MS * attempt;
        log.warn(
            "数据库暂时无法打开（第 {}/{} 次尝试），{}ms 后重试：{}",
            attempt,
            MAX_OPEN_ATTEMPTS,
            delay,
            ex.getMessage());
        try {
          Thread.sleep(delay);
        } catch (InterruptedException interrupted) {
          Thread.currentThread().interrupt();
          throw new IllegalStateException("旧数据项目字段迁移在重试等待时被中断", interrupted);
        }
      }
    }
    // Unreachable: the loop either returns or throws, but keep the compiler and readers happy.
    throw new IllegalStateException("旧数据项目字段迁移失败，已停止启动以避免使用不完整授权数据", lastOpenFailure);
  }

  private void runMigration(Connection connection) throws SQLException {
    boolean previousAutoCommit = connection.getAutoCommit();
    connection.setAutoCommit(false);
    try {
      Map<Long, Set<Long>> projectsByTarget = loadUnambiguousProjectCandidates(connection);
      MigrationResult tasks = migrateTable(connection, TASKS, projectsByTarget, true);
      MigrationResult schedules = migrateTable(connection, SCHEDULES, projectsByTarget, false);
      connection.commit();
      if (tasks.changed() || schedules.changed()) {
        log.info(
            "Legacy project schema migrated: tasks backfilled={}, tasks removed={}, "
                + "schedules backfilled={}, schedules removed={}",
            tasks.backfilled(),
            tasks.removed(),
            schedules.backfilled(),
            schedules.removed());
      }
    } catch (SQLException | RuntimeException ex) {
      connection.rollback();
      throw ex;
    } finally {
      connection.setAutoCommit(previousAutoCommit);
    }
  }

  /**
   * Distinguishes a database that is momentarily unavailable (file still locked by a terminating
   * process, or the H2 store is still initializing) from a genuine schema/data error. Only the
   * former is worth retrying; the latter must stay fatal so we never run on partial data.
   */
  private boolean isTransientOpenFailure(SQLException ex) {
    for (Throwable current = ex; current != null; current = current.getCause()) {
      String message = current.getMessage();
      if (message != null) {
        String lower = message.toLowerCase(Locale.ROOT);
        if (lower.contains("database may be already in use")
            || lower.contains("locked")
            || lower.contains("could not obtain lock")
            || lower.contains("the file is locked")) {
          return true;
        }
      }
      if (current == current.getCause()) {
        break;
      }
    }
    if (ex.getSQLState() != null && ex.getSQLState().startsWith("080")) {
      // 08xxx: SQL connection exception (unable to establish/连接失败).
      return true;
    }
    // H2 maps "database already in use" to error code 90020.
    return ex.getErrorCode() == 90020;
  }

  private MigrationResult migrateTable(
      Connection connection, String table, Map<Long, Set<Long>> projectsByTarget, boolean taskTable)
      throws SQLException {
    if (!tableExists(connection, table)) return MigrationResult.NONE;
    if (!columnExists(connection, table, "project_id")) {
      execute(connection, "ALTER TABLE " + table + " ADD COLUMN project_id BIGINT");
    }
    if (!columnExists(connection, table, "target_id")) {
      int removed = deleteNullProjectRows(connection, table, List.of(), taskTable);
      enforceNotNull(connection, table);
      return new MigrationResult(0, removed, true);
    }

    List<Row> unresolved = new ArrayList<>();
    try (PreparedStatement statement =
            connection.prepareStatement(
                "SELECT id, target_id FROM " + table + " WHERE project_id IS NULL");
        ResultSet rows = statement.executeQuery()) {
      while (rows.next()) unresolved.add(new Row(rows.getLong(1), rows.getLong(2)));
    }

    int backfilled = 0;
    List<Long> removeIds = new ArrayList<>();
    try (PreparedStatement update =
        connection.prepareStatement(
            "UPDATE " + table + " SET project_id = ? WHERE id = ? AND project_id IS NULL")) {
      for (Row row : unresolved) {
        Set<Long> candidates = projectsByTarget.getOrDefault(row.targetId(), Set.of());
        if (candidates.size() == 1) {
          update.setLong(1, candidates.iterator().next());
          update.setLong(2, row.id());
          update.addBatch();
          backfilled++;
        } else {
          removeIds.add(row.id());
        }
      }
      if (backfilled > 0) update.executeBatch();
    }

    int removed = deleteNullProjectRows(connection, table, removeIds, taskTable);
    long remaining = countNullProjects(connection, table);
    if (remaining != 0) {
      throw new SQLException("表 " + table + " 仍有 " + remaining + " 条记录无法关联评估项目");
    }
    enforceNotNull(connection, table);
    return new MigrationResult(backfilled, removed, !unresolved.isEmpty());
  }

  private int deleteNullProjectRows(
      Connection connection, String table, List<Long> expectedIds, boolean taskTable)
      throws SQLException {
    if (taskTable) {
      if (tableExists(connection, "findings") && columnExists(connection, "findings", "task_id")) {
        execute(
            connection,
            "DELETE FROM findings WHERE task_id IN "
                + "(SELECT id FROM security_tasks WHERE project_id IS NULL)");
      }
      if (columnExists(connection, TASKS, "source_task_id")) {
        execute(
            connection,
            "UPDATE security_tasks SET source_task_id = NULL WHERE source_task_id IN "
                + "(SELECT id FROM security_tasks WHERE project_id IS NULL)");
      }
      nullOptionalReference(connection, "audit_logs", "related_task_id");
      nullOptionalReference(connection, "traffic_suggestions", "task_id");
      nullOptionalReference(connection, "scan_schedules", "last_task_id");
    }
    int removed;
    try (PreparedStatement delete =
        connection.prepareStatement("DELETE FROM " + table + " WHERE project_id IS NULL")) {
      removed = delete.executeUpdate();
    }
    // The list is diagnostic only; deleting by NULL is deliberate so a partially failed prior
    // migration is repaired deterministically on the next startup.
    if (!expectedIds.isEmpty() && removed < expectedIds.size()) {
      log.debug(
          "Legacy cleanup removed {} of {} expected rows from {}",
          removed,
          expectedIds.size(),
          table);
    }
    return removed;
  }

  private void nullOptionalReference(Connection connection, String table, String column)
      throws SQLException {
    if (tableExists(connection, table) && columnExists(connection, table, column)) {
      execute(
          connection,
          "UPDATE "
              + table
              + " SET "
              + column
              + " = NULL WHERE "
              + column
              + " IN (SELECT id FROM security_tasks WHERE project_id IS NULL)");
    }
  }

  private Map<Long, Set<Long>> loadUnambiguousProjectCandidates(Connection connection)
      throws SQLException {
    Map<Long, Set<Long>> result = new HashMap<>();
    if (!tableExists(connection, "assessment_project_targets")
        || !columnExists(connection, "assessment_project_targets", "target_id")
        || !columnExists(connection, "assessment_project_targets", "project_id")
        || !tableExists(connection, "assessment_projects")) {
      return result;
    }
    String sql =
        "SELECT pt.target_id, pt.project_id FROM assessment_project_targets pt "
            + "JOIN assessment_projects p ON p.id = pt.project_id";
    try (Statement statement = connection.createStatement();
        ResultSet rows = statement.executeQuery(sql)) {
      while (rows.next()) {
        result
            .computeIfAbsent(rows.getLong(1), ignored -> new LinkedHashSet<>())
            .add(rows.getLong(2));
      }
    }
    return result;
  }

  private void enforceNotNull(Connection connection, String table) throws SQLException {
    if (columnNullable(connection, table, "project_id")) {
      execute(connection, "ALTER TABLE " + table + " ALTER COLUMN project_id SET NOT NULL");
    }
  }

  private long countNullProjects(Connection connection, String table) throws SQLException {
    try (Statement statement = connection.createStatement();
        ResultSet row =
            statement.executeQuery("SELECT COUNT(*) FROM " + table + " WHERE project_id IS NULL")) {
      row.next();
      return row.getLong(1);
    }
  }

  private boolean tableExists(Connection connection, String table) throws SQLException {
    DatabaseMetaData metadata = connection.getMetaData();
    try (ResultSet tables =
        metadata.getTables(connection.getCatalog(), null, null, new String[] {"TABLE"})) {
      while (tables.next()) {
        if (table.equalsIgnoreCase(tables.getString("TABLE_NAME"))) return true;
      }
    }
    return false;
  }

  private boolean columnExists(Connection connection, String table, String column)
      throws SQLException {
    return columnMetadata(connection, table, column) != null;
  }

  private boolean columnNullable(Connection connection, String table, String column)
      throws SQLException {
    ColumnMetadata metadata = columnMetadata(connection, table, column);
    return metadata != null && metadata.nullable();
  }

  private ColumnMetadata columnMetadata(Connection connection, String table, String column)
      throws SQLException {
    DatabaseMetaData metadata = connection.getMetaData();
    try (ResultSet columns = metadata.getColumns(connection.getCatalog(), null, null, null)) {
      while (columns.next()) {
        if (table.equalsIgnoreCase(columns.getString("TABLE_NAME"))
            && column.equalsIgnoreCase(columns.getString("COLUMN_NAME"))) {
          return new ColumnMetadata(columns.getInt("NULLABLE") != DatabaseMetaData.columnNoNulls);
        }
      }
    }
    return null;
  }

  private void execute(Connection connection, String sql) throws SQLException {
    try (Statement statement = connection.createStatement()) {
      statement.executeUpdate(sql);
    }
  }

  private record Row(long id, long targetId) {}

  private record ColumnMetadata(boolean nullable) {}

  private record MigrationResult(int backfilled, int removed, boolean changed) {
    private static final MigrationResult NONE = new MigrationResult(0, 0, false);
  }
}
