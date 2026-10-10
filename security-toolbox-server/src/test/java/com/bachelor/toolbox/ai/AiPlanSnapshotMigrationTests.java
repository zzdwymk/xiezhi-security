package com.bachelor.toolbox.ai;

import static org.assertj.core.api.Assertions.assertThat;

import java.sql.DriverManager;
import java.util.UUID;
import org.hibernate.boot.MetadataSources;
import org.hibernate.boot.registry.StandardServiceRegistryBuilder;
import org.junit.jupiter.api.Test;

/** Exercises the shipped ddl-auto=update policy against a pre-snapshot schema, without real data. */
class AiPlanSnapshotMigrationTests {
  @Test
  void nullableSnapshotMigrationAndRestartPreserveLegacyConversationRows() throws Exception {
    String url = "jdbc:h2:mem:plan-migration-" + UUID.randomUUID() + ";DB_CLOSE_DELAY=-1";
    try (var connection = DriverManager.getConnection(url, "sa", "");
        var statement = connection.createStatement()) {
      statement.execute("create table ai_conversation_sessions (id varchar(64) primary key, "
          + "project_id bigint not null, target_id bigint not null, turns_json text not null, "
          + "last_access timestamp with time zone not null)");
      statement.execute("insert into ai_conversation_sessions values "
          + "('legacy',101,202,'[{\"user\":true,\"text\":\"keep original question\"}]',current_timestamp)");
    }
    updateSchema(url);
    try (var connection = DriverManager.getConnection(url, "sa", "");
        var statement = connection.createStatement()) {
      try (var rows = statement.executeQuery("select turns_json,last_plan_json from ai_conversation_sessions where id='legacy'")) {
        assertThat(rows.next()).isTrue();
        assertThat(rows.getString(1)).contains("keep original question");
        assertThat(rows.getString(2)).isNull();
      }
      statement.executeUpdate("update ai_conversation_sessions set last_plan_json='{\"version\":1}' where id='legacy'");
    }
    updateSchema(url);
    try (var connection = DriverManager.getConnection(url, "sa", "");
        var statement = connection.createStatement();
        var rows = statement.executeQuery("select turns_json,last_plan_json from ai_conversation_sessions")) {
      assertThat(rows.next()).isTrue();
      assertThat(rows.getString(1)).contains("keep original question");
      assertThat(rows.getString(2)).isEqualTo("{\"version\":1}");
      assertThat(rows.next()).isFalse();
    }
  }

  private void updateSchema(String url) {
    var registry = new StandardServiceRegistryBuilder()
        .applySetting("hibernate.connection.url", url)
        .applySetting("hibernate.connection.username", "sa")
        .applySetting("hibernate.connection.password", "")
        .applySetting("hibernate.hbm2ddl.auto", "update")
        .applySetting("hibernate.physical_naming_strategy",
            "org.hibernate.boot.model.naming.CamelCaseToUnderscoresNamingStrategy")
        .build();
    try (var factory = new MetadataSources(registry).addAnnotatedClass(AiConversationSessionRecord.class)
        .buildMetadata().buildSessionFactory()) {
      assertThat(factory.isOpen()).isTrue();
    } finally {
      StandardServiceRegistryBuilder.destroy(registry);
    }
  }
}
