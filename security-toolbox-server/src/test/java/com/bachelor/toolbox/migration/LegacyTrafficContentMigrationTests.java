package com.bachelor.toolbox.migration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import java.util.zip.GZIPOutputStream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;

class LegacyTrafficContentMigrationTests {
  private JdbcTemplate jdbc;
  private LegacyTrafficContentMigration migration;

  @BeforeEach
  void database() {
    var dataSource = new DriverManagerDataSource(
        "jdbc:h2:mem:traffic-compat-" + UUID.randomUUID() + ";MODE=PostgreSQL;DB_CLOSE_DELAY=-1", "sa", "");
    jdbc = new JdbcTemplate(dataSource);
    migration = new LegacyTrafficContentMigration(dataSource);
  }

  @Test
  void skipsFreshDatabaseAndOriginalInlineSchema() {
    assertThat(migration.migrate()).isZero();
    jdbc.execute("create table traffic_packets(id bigint primary key, request_body text)");
    jdbc.update("insert into traffic_packets values(1, '原文本')");
    assertThat(migration.migrate()).isZero();
    assertThat(jdbc.queryForObject("select request_body from traffic_packets where id=1", String.class)).isEqualTo("原文本");
  }

  @Test
  void restoresAllFourFieldsAndRetainsCompressedContent() throws Exception {
    schema();
    content(1, gzip("GET / HTTP/1.1\r\nCookie: secret"), gzip("请求正文"),
        gzip("HTTP/1.1 200 OK"), gzip("响应正文"));
    packet(1, 1, null);
    assertThat(migration.migrate()).isEqualTo(1);
    var row = jdbc.queryForMap("select * from traffic_packets where id=1");
    assertThat(row.get("REQUEST_HEADERS")).isEqualTo("GET / HTTP/1.1\r\nCookie: secret");
    assertThat(row.get("REQUEST_BODY")).isEqualTo("请求正文");
    assertThat(row.get("RESPONSE_HEADERS")).isEqualTo("HTTP/1.1 200 OK");
    assertThat(row.get("RESPONSE_BODY")).isEqualTo("响应正文");
    assertThat(row.get("CONTENT_ID")).isNull();
    assertThat(jdbc.queryForObject("select count(*) from traffic_packet_contents", Integer.class)).isEqualTo(1);
  }

  @Test
  void existingInlineTextWinsAndMigrationIsIdempotent() throws Exception {
    schema();
    content(1, new byte[0], new byte[] {1, 2, 3}, null, gzip("response"));
    packet(1, 1, "已有正文");
    assertThat(migration.migrate()).isEqualTo(1);
    assertThat(migration.migrate()).isZero();
    assertThat(jdbc.queryForObject("select request_body from traffic_packets where id=1", String.class)).isEqualTo("已有正文");
    assertThat(jdbc.queryForObject("select request_headers from traffic_packets where id=1", String.class)).isEmpty();
  }

  @Test
  void invalidCompressedDataRollsBackBatchWithoutDetachingReferences() throws Exception {
    schema();
    content(1, null, gzip("must roll back"), null, null);
    content(2, null, new byte[] {1, 2, 3}, null, null);
    packet(1, 1, null);
    packet(2, 2, null);
    assertThatThrownBy(migration::migrate).isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("原压缩内容仍保留").hasNoCause();
    assertThat(jdbc.queryForObject("select count(*) from traffic_packets where content_id is not null", Integer.class)).isEqualTo(2);
    assertThat(jdbc.queryForObject("select request_body from traffic_packets where id=1", String.class)).isNull();
  }

  @Test
  void restoresMultipleBatchesWithoutLeavingAnyReferences() throws Exception {
    schema();
    byte[] body = gzip("一条正文");
    for (int id = 1; id <= 205; id++) {
      content(id, null, body, null, new byte[0]);
      packet(id, id, null);
    }
    assertThat(migration.migrate()).isEqualTo(205);
    assertThat(jdbc.queryForObject("select count(*) from traffic_packets where content_id is null and request_body='一条正文'", Integer.class)).isEqualTo(205);
    assertThat(jdbc.queryForObject("select count(*) from traffic_packet_contents", Integer.class)).isEqualTo(205);
    assertThat(migration.migrate()).isZero();
  }

  private void schema() {
    jdbc.execute("create table traffic_packet_contents(id bigint primary key, request_headers_gzip bytea,"
        + " request_body_gzip bytea, response_headers_gzip bytea, response_body_gzip bytea)");
    jdbc.execute("create table traffic_packets(id bigint primary key, content_id bigint references traffic_packet_contents(id),"
        + " request_headers text, request_body text, response_headers text, response_body text)");
  }

  private void content(long id, byte[] requestHeaders, byte[] requestBody, byte[] responseHeaders, byte[] responseBody) {
    jdbc.update("insert into traffic_packet_contents values(?,?,?,?,?)", id, requestHeaders, requestBody, responseHeaders, responseBody);
  }

  private void packet(long id, long contentId, String existingBody) {
    jdbc.update("insert into traffic_packets(id,content_id,request_body) values(?,?,?)", id, contentId, existingBody);
  }

  private static byte[] gzip(String value) throws Exception {
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    try (GZIPOutputStream gzip = new GZIPOutputStream(output)) { gzip.write(value.getBytes(StandardCharsets.UTF_8)); }
    return output.toByteArray();
  }
}
