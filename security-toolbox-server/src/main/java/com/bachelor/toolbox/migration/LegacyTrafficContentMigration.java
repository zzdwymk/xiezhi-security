package com.bachelor.toolbox.migration;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.zip.GZIPInputStream;
import javax.sql.DataSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Restores payloads written by the temporary compressed-storage schema before Hibernate starts. */
public final class LegacyTrafficContentMigration {
  private static final Logger LOG = LoggerFactory.getLogger(LegacyTrafficContentMigration.class);
  private static final int BATCH_SIZE = 100;
  private static final Set<String> PACKET_COLUMNS = Set.of(
      "id", "content_id", "request_headers", "request_body", "response_headers", "response_body");
  private static final Set<String> CONTENT_COLUMNS = Set.of(
      "id", "request_headers_gzip", "request_body_gzip", "response_headers_gzip", "response_body_gzip");
  private final DataSource dataSource;

  public LegacyTrafficContentMigration(DataSource dataSource) { this.dataSource = dataSource; }

  public long migrate() {
    try (Connection connection = dataSource.getConnection()) {
      if (!columns(connection, "traffic_packets").containsAll(PACKET_COLUMNS)
          || !columns(connection, "traffic_packet_contents").containsAll(CONTENT_COLUMNS)) return 0;
      boolean autoCommit = connection.getAutoCommit();
      connection.setAutoCommit(false);
      long migrated = 0;
      try {
        long after = 0;
        while (true) {
          List<Reference> batch = references(connection, after);
          if (batch.isEmpty()) break;
          for (Reference reference : batch) restorePayload(connection, reference);
          // Make all restored TEXT durable before detaching the old payload references.
          connection.commit();
          clearReferences(connection, batch);
          connection.commit();
          migrated += batch.size();
          after = batch.get(batch.size() - 1).packetId();
        }
      } catch (SQLException | IOException | RuntimeException failure) {
        connection.rollback();
        // SQL exception messages can contain parameter values. Never attach them to startup logs.
        throw new IllegalStateException("历史流量正文兼容恢复失败，已停止启动；原压缩内容仍保留");
      } finally {
        connection.setAutoCommit(autoCommit);
      }
      if (migrated > 0) LOG.info("历史流量正文已兼容恢复，报文数={}", migrated);
      return migrated;
    } catch (SQLException failure) {
      throw new IllegalStateException("历史流量正文兼容恢复无法访问数据库，已停止启动；SQLState=" + failure.getSQLState());
    }
  }

  private static Set<String> columns(Connection connection, String table) throws SQLException {
    Set<String> result = new HashSet<>();
    try (PreparedStatement statement = connection.prepareStatement(
        "select column_name from information_schema.columns"
            + " where table_schema = current_schema() and lower(table_name) = ?")) {
      statement.setString(1, table);
      try (ResultSet rows = statement.executeQuery()) {
        while (rows.next()) result.add(rows.getString(1).toLowerCase(Locale.ROOT));
      }
    }
    return result;
  }

  private static List<Reference> references(Connection connection, long after) throws SQLException {
    List<Reference> result = new ArrayList<>(BATCH_SIZE);
    try (PreparedStatement statement = connection.prepareStatement(
        "select id, content_id from traffic_packets where content_id is not null and id > ? order by id")) {
      statement.setLong(1, after);
      statement.setMaxRows(BATCH_SIZE);
      try (ResultSet rows = statement.executeQuery()) {
        while (rows.next()) result.add(new Reference(rows.getLong(1), rows.getLong(2)));
      }
    }
    return result;
  }

  private static void restorePayload(Connection connection, Reference reference) throws SQLException, IOException {
    // Only one packet's payload is materialized at a time, regardless of the batch size.
    try (PreparedStatement select = connection.prepareStatement(
        "select p.request_headers, p.request_body, p.response_headers, p.response_body,"
            + " c.request_headers_gzip, c.request_body_gzip, c.response_headers_gzip, c.response_body_gzip"
            + " from traffic_packets p join traffic_packet_contents c on c.id = p.content_id"
            + " where p.id = ? and p.content_id = ?")) {
      select.setLong(1, reference.packetId());
      select.setLong(2, reference.contentId());
      try (ResultSet row = select.executeQuery()) {
        if (!row.next()) throw new IllegalStateException("历史流量内容引用不存在");
        String[] text = new String[4];
        for (int index = 0; index < text.length; index++) {
          text[index] = row.getString(index + 1);
          if (text[index] == null) text[index] = decompress(row.getBytes(index + 5));
        }
        try (PreparedStatement update = connection.prepareStatement(
            "update traffic_packets set request_headers = coalesce(request_headers, ?),"
                + " request_body = coalesce(request_body, ?), response_headers = coalesce(response_headers, ?),"
                + " response_body = coalesce(response_body, ?) where id = ? and content_id = ?")) {
          for (int index = 0; index < text.length; index++) {
            if (text[index] == null) update.setNull(index + 1, Types.VARCHAR);
            else update.setString(index + 1, text[index]);
          }
          update.setLong(5, reference.packetId());
          update.setLong(6, reference.contentId());
          update.executeUpdate();
        }
      }
    }
  }

  private static void clearReferences(Connection connection, List<Reference> batch) throws SQLException {
    try (PreparedStatement statement = connection.prepareStatement(
        "update traffic_packets set content_id = null where id = ? and content_id = ?")) {
      for (Reference reference : batch) {
        statement.setLong(1, reference.packetId());
        statement.setLong(2, reference.contentId());
        statement.addBatch();
      }
      statement.executeBatch();
    }
  }

  private static String decompress(byte[] compressed) throws IOException {
    if (compressed == null) return null;
    if (compressed.length == 0) return "";
    try (GZIPInputStream gzip = new GZIPInputStream(new ByteArrayInputStream(compressed))) {
      return new String(gzip.readAllBytes(), StandardCharsets.UTF_8);
    }
  }

  private record Reference(long packetId, long contentId) {}
}
