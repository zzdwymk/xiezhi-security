package com.bachelor.toolbox.migration;

import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Types;
import java.util.Map;
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
  private static final String PROGRESS_FILE_PROPERTY = "toolbox.migration.legacy-h2-progress-file";

  // 迁移进度写入的 UTF-8 文件；electron 主进程会实时 tail 并转发给前端“迁移进度”面板。
  private static java.nio.file.Path progressFile() {
    String v = System.getenv("LEGACY_H2_MIGRATE_PROGRESS_FILE");
    if (v == null || v.isBlank()) v = System.getProperty(PROGRESS_FILE_PROPERTY);
    return (v == null || v.isBlank()) ? null : java.nio.file.Paths.get(v.trim());
  }

  private static void writeProgress(String line) {
    log.info("MIGRATE: {}", line);
    java.nio.file.Path p = progressFile();
    if (p == null) return;
    try {
      java.nio.file.Files.write(
          p,
          (java.time.LocalTime.now().plusHours(8) + " | " + line + "\n").getBytes(java.nio.charset.StandardCharsets.UTF_8),
          java.nio.file.StandardOpenOption.CREATE,
          java.nio.file.StandardOpenOption.APPEND);
    } catch (java.io.IOException ex) {
      log.warn("无法写入迁移进度文件 {}: {}", p, ex.getMessage());
    }
  }

  // 业务数据表按外键依赖排序：先父表（用户/项目/目标），再依赖它们的任务/结果/操作等子表，
  // 拷贝时保持主键，因此关系可在目标库继续成立。表名需与后端 @Table 及 H2 源一致。
  private static final List<String> WHITELIST =
      List.of(
          // 用户与权限
          "app_users",
          // 项目、目标及其关联
          "assessment_projects",
          "authorized_targets",
          "assessment_project_targets",
          "project_approvals",
          // 独立配置/规则
          "detection_rules",
          "task_execution_settings",
          // 审计
          "audit_logs",
          // 扫描任务（依赖项目/目标）
          "security_tasks",
          // 漏洞结果（依赖任务/目标）
          "findings",
          // 指纹探测结果（依赖项目/目标）
          "probe_results",
          // 操作记录（依赖项目/目标/漏洞）
          "security_actions",
          // 后渗透路径（依赖目标/项目/漏洞/任务）
          "post_scan_paths",
          // 流量会话及记录（后依赖：会话→报文→建议/台账）
          "traffic_sessions",
          "traffic_packets",
          "traffic_suggestions",
          "traffic_scan_ledger",
          "traffic_capture_filters",
          // AI 会话与代理分发（依赖项目/目标）
          "ai_conversation_sessions",
          "ai_agent_dispatches");

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
    writeProgress("开始导入：正在连接 H2 源与 PostgreSQL 目标…");
    try (Connection source = openLegacyConnection(legacyUrl);
        Connection target = postgresDataSource.getConnection()) {
      Set<String> available = presentTables(source);
      Set<String> presentTarget = presentTables(target);
      long totalRows = 0;
      writeProgress(
          String.format("已连接 target=security_toolbox，共发现 %d 张白名单核心表", available.size()));
      target.setAutoCommit(false);
      try {
        for (String raw : WHITELIST) {
          String table = raw.toLowerCase(Locale.ROOT);
          if (!available.contains(table)) continue;
          if (!presentTarget.contains(table)) {
            createTargetTable(target, source, table);
            presentTarget.add(table);
            writeProgress("表 " + table + " 在目标库不存在，已按 H2 结构自动创建（空表）");
          }
          if (targetHasRows(target, table)) {
            writeProgress("表 " + table + " 目标库已有数据，跳过拷贝");
            continue;
          }
          writeProgress("正在导入表 " + table + " …");
          int rows;
          try {
            normalizeLobTextColumns(source, target, table);
            rows = copyTable(source, target, table);
          } catch (SQLException ex) {
            writeProgress("表 " + table + " 导入失败：" + ex.getMessage());
            throw ex;
          }
          totalRows += rows;
          writeProgress(
              String.format("表 %s 导入完成：%d 行（累计 %d 行）", table, rows, totalRows));
        }
        target.commit();
        writeProgress("全部导入完成，事务已提交。");
      } catch (SQLException | RuntimeException ex) {
        target.rollback();
        writeProgress("导入失败，已回滚：" + ex.getMessage());
        throw ex;
      } finally {
        target.setAutoCommit(true);
      }
      return (int) totalRows;
    } catch (SQLException ex) {
      writeProgress("导入失败，请检查 H2 文件与 PostgreSQL 连接：" + ex.getMessage());
      throw new IllegalStateException("H2→PostgreSQL 数据迁移失败，请检查 H2 文件与 PostgreSQL 连接", ex);
    }
  }

  private static String currentDatabase(Connection c) throws SQLException {
    try (Statement st = c.createStatement();
        ResultSet rs = st.executeQuery("SELECT current_database(), current_user, current_schema()")) {
      rs.next();
      return rs.getString(1) + " (user=" + rs.getString(2) + ", current_schema=" + rs.getString(3) + ")";
    }
  }

  private static String discoverSchema(Connection c) throws SQLException {
    StringBuilder sb = new StringBuilder();
    try (Statement st = c.createStatement();
        ResultSet rs =
            st.executeQuery(
                "SELECT table_schema, table_name FROM information_schema.tables WHERE table_type='BASE TABLE' AND table_schema NOT IN ('pg_catalog','information_schema') ORDER BY 1,2")) {
      while (rs.next()) {
        sb.append(rs.getString(1)).append('.').append(rs.getString(2)).append('\n');
      }
    }
    return sb.toString();
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

  // H2 里用 CLOB 存的长文本列，在 PostgreSQL 端常被 Hibernate 的 @Lob 建成 oid（大对象）类型。
  // 直接把 String 绑进 oid 列会报 “column is of type oid but expression is of type character varying”。
  // 这里在拷贝前把这类列的 OID/OID 大对象类型改成 TEXT，让两者都以文本承载，避免类型冲突。
  private static void normalizeLobTextColumns(Connection source, Connection target, String table)
      throws SQLException {
    Map<String, String> targetTypes = targetColumnTypes(target, table);
    if (targetTypes.isEmpty()) return;
    List<Column> columns = tableColumns(source, table);
    for (Column c : columns) {
      String t = c.pgType();
      // 源侧是长文本，而目标侧是大对象（oid）时，改写目标列为 TEXT。
      boolean sourceIsTextLike =
          t.contains("TEXT") || t.contains("VARCHAR") || t.contains("CHAR") || t.contains("CLOB");
      String tt = targetTypes.getOrDefault(c.name(), "").toUpperCase(Locale.ROOT);
      boolean targetIsLob = tt.contains("OID") || tt.contains("LARGE") || tt.equals("BLOB");
      if (sourceIsTextLike && targetIsLob) {
        try (Statement st = target.createStatement()) {
          st.execute("ALTER TABLE " + table + " ALTER COLUMN " + quoted(c.name()) + " TYPE TEXT");
        }
        writeProgress("列 " + table + "." + c.name() + " 目标类型为 oid，已改写为 TEXT");
      }
    }
  }

  private static Map<String, String> targetColumnTypes(Connection target, String table)
      throws SQLException {
    DatabaseMetaData metadata = target.getMetaData();
    Map<String, String> map = new java.util.concurrent.ConcurrentHashMap<>();
    try (ResultSet cols = metadata.getColumns(target.getCatalog(), null, table, "%")) {
      while (cols.next()) {
        String name = cols.getString("COLUMN_NAME");
        if (name != null) {
          map.put(name.toLowerCase(Locale.ROOT), cols.getString("TYPE_NAME"));
        }
      }
    }
    return map;
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
          int sqlType = src.getMetaData().getColumnType(i + 1);
          Object raw = src.getObject(i + 1);
          if (raw == null) {
            insert.setNull(i + 1, sqlType);
          } else if (raw instanceof byte[]) {
            insert.setBytes(i + 1, (byte[]) raw);
          } else {
            // 按源列的类型绑定（而非一律字符串），让 PostgreSQL 收到与目标列一致的原生类型
            //（如 bigint/timestamp/numeric），避免 “column is of type bigint but expression is varchar”。
            switch (sqlType) {
              case Types.BIGINT, Types.INTEGER, Types.SMALLINT, Types.TINYINT ->
                  insert.setObject(i + 1, Long.valueOf(String.valueOf(raw).trim()), sqlType);
              case Types.NUMERIC, Types.DECIMAL ->
                  insert.setBigDecimal(i + 1, new java.math.BigDecimal(String.valueOf(raw).trim()));
              case Types.BOOLEAN, Types.BIT ->
                  insert.setBoolean(i + 1, Boolean.parseBoolean(String.valueOf(raw).trim()));
case Types.DATE, Types.TIMESTAMP, Types.TIME, Types.TIMESTAMP_WITH_TIMEZONE,
                  Types.TIME_WITH_TIMEZONE ->
                  insert.setObject(i + 1, convertTemporal(raw, sqlType), sqlType);
              case Types.CLOB, Types.LONGVARCHAR, Types.NCLOB, Types.LONGNVARCHAR ->
                  insert.setString(i + 1, sanitizeText(src.getString(i + 1)));
              default -> insert.setString(i + 1, sanitizeText(String.valueOf(raw)));
            }
          }
        }
        insert.addBatch();
        rows++;
        if (rows % 500 == 0) {
          insert.executeBatch();
          writeProgress(String.format("表 %s 已导入 %d 行…", table, rows));
        }
      }
      insert.executeBatch();
    }
    bumpIdentity(target, table, columns);
    return rows;
  }

  // PostgreSQL 的 text/varchar 不允许包含 \u0000 空字节，也不接受非 UTF-8 字节序列。
  // 流量抓包的原始头/体里常混有 0x00 及二进制碎片，入库前清洗成合法 UTF-8 文本，避免整批回滚。
  private static String sanitizeText(String s) {
    if (s == null) return null;
    String cleaned = s.replace("\u0000", "");
    return new String(cleaned.getBytes(java.nio.charset.StandardCharsets.UTF_8),
        java.nio.charset.StandardCharsets.UTF_8);
  }

  private static Object convertTemporal(Object raw, int sqlType) {
    String s = String.valueOf(raw).trim();
    // 优先按带时区的 OffsetDateTime 解析（H2 常返回 “2026-08-28T16:00Z” 这类字面量），
    // 再回落 LocalDateTime / 纯日期。解析失败返回当前时间兜底，保证整批不因坏值中断。
    try {
      return java.time.OffsetDateTime.parse(s);
    } catch (RuntimeException ignored) {}
    try {
      return java.time.LocalDateTime.parse(s.replace(' ', 'T'));
    } catch (RuntimeException ignored) {}
    try {
      return java.time.LocalDate.parse(s.substring(0, 10));
    } catch (RuntimeException ignored) {}
    return java.time.LocalDateTime.now();
  }

  private static List<Column> tableColumns(Connection connection, String table) throws SQLException {
    // H2 把未加引号的标识符存为大写；这里用一个区分大小写无关的解析，确保列查询命中。
    String actual = resolveTableName(connection, table);
    if (actual == null) return List.of();
    DatabaseMetaData metadata = connection.getMetaData();
    List<Column> columns = new ArrayList<>();
    try (ResultSet cols = metadata.getColumns(connection.getCatalog(), null, actual, "%")) {
      while (cols.next()) {
        String name = cols.getString("COLUMN_NAME");
        // H2 元数据返回大写列名，而 PostgreSQL 端 Hibernate 建的表是全部小写的。
        // 统一用小写，保证 INSERT 时目标列名与 PG 端（未加引号折叠为小写）匹配。
        name = name == null ? null : name.toLowerCase(Locale.ROOT);
        boolean auto = "YES".equalsIgnoreCase(cols.getString("IS_AUTOINCREMENT"));
        String typeName = cols.getString("TYPE_NAME");
        int size = cols.getInt("COLUMN_SIZE");
        boolean nullable = cols.getInt("NULLABLE") == DatabaseMetaData.columnNullable;
        columns.add(new Column(name, auto, toPostgresType(typeName, size), nullable));
      }
    }
    return columns;
  }

  // 返回给定表名在连接里实际（大小写与原样一致）的表名；找不到返回 null。
  private static String resolveTableName(Connection connection, String table) throws SQLException {
    DatabaseMetaData metadata = connection.getMetaData();
    try (ResultSet tables =
        metadata.getTables(connection.getCatalog(), null, "%", new String[] {"TABLE"})) {
      while (tables.next()) {
        String name = tables.getString("TABLE_NAME");
        if (name != null && name.equalsIgnoreCase(table)) return name;
      }
    }
    return null;
  }

  // 把 H2 的列类型尽量映射成 PostgreSQL 可用的类型。多数枚举 / 数值 / 时间在两种方言里同名，
  // 只要常见类型覆盖到位，镜像出的 PG 表就能承载拷贝来的行。
  private static String toPostgresType(String h2Type, int size) {
    if (h2Type == null) return "BYTEA";
    String t = h2Type.trim().toUpperCase(Locale.ROOT);
    if (t.contains("VARCHAR") || t.contains("CHAR") || t.contains("TEXT") || t.contains("CLOB")) {
      if (t.contains("VARCHAR") && size > 0 && size <= 4000) return "VARCHAR(" + size + ")";
      if (t.contains("CHAR") && size > 0) return "VARCHAR(" + size + ")";
      return "TEXT";
    }
    if (t.equals("BIGINT") || t.equals("LONG") || t.equals("INT8")) return "BIGINT";
    if (t.equals("INTEGER") || t.equals("INT") || t.equals("INT4") || t.equals("MEDIUMINT"))
      return "INTEGER";
    if (t.equals("SMALLINT") || t.equals("INT2")) return "SMALLINT";
    if (t.equals("TINYINT") || t.equals("BOOLEAN") || t.equals("BIT")) return "BOOLEAN";
    if (t.contains("TIMESTAMP") || t.equals("DATETIME")) return "TIMESTAMP";
    if (t.equals("DATE")) return "DATE";
    if (t.equals("TIME")) return "TIME";
    if (t.contains("NUMERIC") || t.equals("DECIMAL") || t.equals("DEC") || t.equals("NUMBER"))
      return size > 0 ? "NUMERIC(" + Math.min(size, 1000) + ",0)" : "NUMERIC";
    if (t.contains("DOUBLE") || t.equals("FLOAT") || t.equals("REAL")) return "DOUBLE PRECISION";
    if (t.contains("BINARY") || t.contains("BYTEA") || t.equals("VARBINARY") || t.contains("BLOB"))
      return "BYTEA";
    if (t.contains("UUID")) return "UUID";
    if (t.equals("JSON") || t.equals("JSONB")) return "JSONB";
    if (t.equals("OTHER") || t.equals("OBJECT")) return "BYTEA";
    return "BYTEA";
  }

  // 按 H2 源表的列/类型/可空性，在目标库创建同名表（不建外键，仅承载拷贝来的行；
  // 主键/自增列保留为 BIGINT/INTEGER + GENERATED BY DEFAULT AS IDENTITY，方便拷贝后 setval）。
  private static void createTargetTable(Connection target, Connection source, String table)
      throws SQLException {
    List<Column> columns = tableColumns(source, table);
    if (columns.isEmpty()) {
      log.warn("表 {} 在 H2 中无列，跳过自动建表", table);
      return;
    }
    StringBuilder ddl = new StringBuilder("CREATE TABLE ").append(table).append(" (");
    boolean first = true;
    Column identity = columns.stream().filter(Column::isAuto).findFirst().orElse(null);
    for (Column c : columns) {
      if (!first) ddl.append(", ");
      first = false;
      ddl.append(quoted(c.name())).append(' ').append(c.pgType());
      if (identity != null && identity.name().equals(c.name())) {
        boolean integral = c.pgType().startsWith("INTEGER") || c.pgType().startsWith("BIGINT")
            || c.pgType().startsWith("SMALLINT");
        if (integral) {
          ddl.append(" GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY");
          continue;
        }
        ddl.append(" PRIMARY KEY");
        continue;
      }
      if (!c.nullable()) ddl.append(" NOT NULL");
    }
    ddl.append(')');
    try (Statement st = target.createStatement()) {
      st.executeUpdate(ddl.toString());
    }
  }

  // H2 与 PostgreSQL 对未加引号的标识符都做大小写折叠（H2→大写，PG→小写）。
// 这里统一用“裸名”（不加引号）生成 SQL，让同一列名在源(H2)和目标(PG)都能命中，
// 避免引号导致的大小写严格匹配在两库之间不一致。
  private static String quoted(String name) {
    return name == null ? "" : name.toLowerCase(Locale.ROOT);
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
    try (Statement statement = target.createStatement();
        ResultSet row =
            statement.executeQuery(
                "SELECT setval(pg_get_serial_sequence('"
                    + table
                    + "', '"
                    + identity.replace("'", "''")
                    + "'), "
                    + next
                    + ", false)")) {
      // setval 返回一行，用 executeQuery 读取并消费结果，避免 executeUpdate 报“传回预期之外的结果”。
      while (row.next()) {
        // just advance the cursor
      }
    }
  }

  private record Column(String name, boolean isAuto, String pgType, boolean nullable) {}
}