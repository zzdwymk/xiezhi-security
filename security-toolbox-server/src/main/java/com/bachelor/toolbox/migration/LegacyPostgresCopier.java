package com.bachelor.toolbox.migration;

import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import javax.sql.DataSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Copies rows of core business tables from a legacy H2 file database into the running PostgreSQL.
 *
 * <p>The desktop app has traditionally stored its data in an H2 file started in PostgreSQL
 * compatibility mode. When the user opts to switch to a real PostgreSQL instance this service
 * imports the existing rows so nothing is lost. It runs after Hibernate has created/updated the
 * target schema ({@code ddl-auto: update}) and only when a legacy H2 URL is supplied.
 *
 * <ul>
 *   <li>Source URL comes from the {@code LEGACY_H2_MIGRATE_URL} environment variable or the {@code
 *       toolbox.migration.legacy-h2-url} system property; when absent nothing runs.
 *   <li>Each whitelisted table is copied only if the PostgreSQL target table is currently empty,
 *       making the copy idempotent and safe to retry after a partial failure.
 *   <li>Values are copied positionally and primary keys are preserved so the relations stay
 *       intact; the PostgreSQL identity sequence is then advanced past the largest imported id.
 *   <li>The legacy H2 file is left untouched so the user can switch back.
 * </ul>
 */
public final class LegacyPostgresCopier {
  private static final Logger log = LoggerFactory.getLogger(LegacyPostgresCopier.class);
  private static final String MIGRATE_URL_PROPERTY = "toolbox.migration.legacy-h2-url";

  // Core business tables (auth, projects, targets, audit). Scan/session artifacts are excluded:
  // they are either regenerated or need a foreign-key ordering pass that is out of scope.
  private static final List<String> WHITELIST =
      List.of(
          "users",
          "assessment_projects",
          "assessment_project_targets",
          "project_approvals",
          "project_targets",
          "authorized_targets",
          "audit_logs");

  private final DataSource postgresDataSource;

  public LegacyPostgresCopier(DataSource postgresDataSource) {
    this.postgresDataSource = postgresDataSource;
  }

  static String resolveMigrateUrl() {
    String value = System.getenv("LEGACY_H2_MIGRATE_URL");
    if (value == null || value.isBlank()) {
      value = System.getProperty(MIGRATE_URL_PROPERTY);
    }
    return (value == null || value.isBlank()) ? null : value.trim();
  }

  public int run() {
    String legacyUrl = resolveMigrateUrl();
    if (legacyUrl == null) {
      log.info("未配置 {}，跳过 H2→PostgreSQL 数据拷贝。", MIGRATE_URL_PROPERTY);
      return 0;
    }
    try (Connection source = openLegacyConnection(legacyUrl);
        Connection target = postgresDataSource.getConnection()) {
      Set<String> available = presentTables(source);
      int copiedTables = 0;
      int copiedRows = 0;
      target.setAutoCommit(false);
      try {
        for (String raw : WHITELIST) {
          String table = raw.toLowerCase(Locale.ROOT);
          if (!available.contains(table)) continue;
          if (targetHasRows(target, table)) {
            log.info("PostgreSQL 表 {} 已有数据，跳过拷贝", table);
            continue;
          }
          copiedRows += copyTable(source, target, table);
          copiedTables++;
        }
        target.commit();
      } catch (SQLException | RuntimeException ex) {
        target.rollback();
        throw ex;
      } finally {
        target.setAutoCommit(true);
      }
      log.info(
          "H2→PostgreSQL 数据迁移完成：共 {} 张表、{} 行；H2 文件已保留，可在设置中回退。",
          copiedTables,
          copiedRows);
      return copiedRows;
    } catch (SQLException ex) {
      throw new IllegalStateException("H2→PostgreSQL 数据迁移失败，请检查 H2 文件与 PostgreSQL 连接", ex);
    }
  }

  private static Connection openLegacyConnection(String url) throws SQLException {
    try {
      Class.forName("org.h2.Driver");
    } catch (ClassNotFoundException ex) {
      throw new SQLException("缺少 H2 JDBC 驱动", ex);
    }
    return DriverManager.getConnection(url, "sa", "");
  }

  private Set<String> presentTables(Connection connection) throws SQLException {
    Set<String> names = new LinkedHashSet<>();
    DatabaseMetaData metadata = connection.getMetaData();
    try (ResultSet tables =
        metadata.getTables(connection.getCatalog(), null, "%", new String[] {"TABLE"})) {
      while (tables.next()) {
        String name = tables.getString("TABLE_NAME");
        if (name != null) names.add(name.toLowerCase(Locale.ROOT));
      }
    }
    return names;
  }

  private boolean targetHasRows(Connection target, String table) throws SQLException {
    try (Statement statement = target.createStatement();
        ResultSet row = statement.executeQuery("SELECT 1 FROM " + table + " LIMIT 1")) {
      return row.next();
    }
  }

  private int copyTable(Connection source, Connection target, String table) throws SQLException {
    List<Column> columns = tableColumns(source, table);
    if (columns.isEmpty()) return 0;
    String selectSql =
        "SELECT "
            + String.join(",", columns.stream().map(c -> quoted(c.name())).toList())
            + " FROM "
            + table;
    String insertSql = buildInsertSql(table, columns);
    int rows = 0;
    try (Statement select = source.createStatement();
        ResultSet src = select.executeQuery(selectSql);
        PreparedStatement insert = target.prepareStatement(insertSql)) {
      while (src.next()) {
        for (int i = 0; i < columns.size(); i++) {
          Object raw = src.getObject(i + 1);
          if (raw == null) {
            insert.setNull(i + 1, src.getMetaData().getColumnType(i + 1));
          } else if (raw instanceof byte[]) {
            insert.setBytes(i + 1, (byte[]) raw);
          } else {
            insert.setString(i + 1, String.valueOf(raw));
          }
        }
        insert.addBatch();
        rows++;
        if (rows % 500 == 0) insert.executeBatch();
      }
      insert.executeBatch();
    }
    bumpIdentity(target, table, columns);
    return rows;
  }

  private static List<Column> tableColumns(Connection connection, String table) throws SQLException {
    List<Column> columns = new ArrayList<>();
    DatabaseMetaData metadata = connection.getMetaData();
    try (ResultSet cols = metadata.getColumns(connection.getCatalog(), null, table, "%")) {
      while (cols.next()) {
        String name = cols.getString("COLUMN_NAME");
        boolean auto = "YES".equalsIgnoreCase(cols.getString("IS_AUTOINCREMENT"));
        columns.add(new Column(name, auto));
      }
    }
    return columns;
  }

  private static String quoted(String name) {
    return "\"" + name.replace("\"", "\"\"") + "\"";
  }

  private static String buildInsertSql(String table, List<Column> columns) {
    String names = String.join(",", columns.stream().map(c -> quoted(c.name())).toList());
    String marks = String.join(",", columns.stream().map(c -> "?").toList());
    return "INSERT INTO " + table + " (" + names + ") VALUES (" + marks + ")";
  }

  private static void bumpIdentity(Connection target, String table, List<Column> columns)
      throws SQLException {
    String identity = columns.stream().filter(Column::isAuto).map(Column::name).findFirst().orElse(null);
    if (identity == null) return;
    long next;
    try (Statement statement = target.createStatement();
        ResultSet row =
            statement.executeQuery(
                "SELECT COALESCE(MAX(" + quoted(identity) + "), 0) + 1 FROM " + table)) {
      row.next();
      next = Math.max(1L, row.getLong(1));
    }
    try (Statement statement = target.createStatement()) {
      statement.executeUpdate(
          "SELECT setval(pg_get_serial_sequence('"
              + table
              + "', '"
              + identity.replace("'", "''")
              + "'), "
              + next
              + ", false)");
    }
  }

  private record Column(String name, boolean isAuto) {}
}