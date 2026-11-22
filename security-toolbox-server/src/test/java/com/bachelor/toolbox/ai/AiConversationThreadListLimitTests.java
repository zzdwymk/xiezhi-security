package com.bachelor.toolbox.ai;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * 第309轮：对话线程列表必须有数量上限。
 *
 * <p>{@code listAllPersistedThreads()} 原实现一次性读取全部会话记录并逐条把 {@code thread_json}
 * 反序列化成 Map。线程数量没有上限，单条线程又允许到 512000 字符（R308），长期使用后一次列表请求
 * 即可造成明显内存放大。列表接口应只返回最近的一批。
 */
@DataJpaTest(
    properties = {
      "spring.datasource.url=jdbc:h2:mem:conversation-list-limit;MODE=PostgreSQL;DB_CLOSE_DELAY=-1",
      "spring.jpa.hibernate.ddl-auto=create-drop"
    })
@Transactional(propagation = Propagation.NOT_SUPPORTED)
class AiConversationThreadListLimitTests {
  @Autowired private AiConversationSessionRepository repository;

  @BeforeEach
  void clear() {
    repository.deleteAll();
  }

  private AiConversationMemoryService service() {
    return new AiConversationMemoryService(
        20, 20, 120, repository, new ObjectMapper(), null);
  }

  @Test
  void listingThreadsIsBounded() {
    for (int i = 0; i < 250; i++) {
      AiConversationSessionRecord record = new AiConversationSessionRecord();
      record.setId("thread-" + i);
      record.setCreatedAt(Instant.now().minusSeconds(1000 - i));
      record.setLastAccess(Instant.now().minusSeconds(1000 - i));
      record.setThreadJson("{\"id\":\"thread-" + i + "\",\"title\":\"t" + i + "\",\"messages\":[]}");
      record.setTurnsJson("[]");
      repository.save(record);
    }
    repository.flush();

    List<Map<String, Object>> threads = service().listAllPersistedThreads();

    assertThat(threads)
        .as("线程列表必须有数量上限，否则一次请求会把全部历史对话读入内存")
        .hasSizeLessThanOrEqualTo(200);
    assertThat(threads).isNotEmpty();
  }
}
