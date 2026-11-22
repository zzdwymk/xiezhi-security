package com.bachelor.toolbox.ai;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

import com.bachelor.toolbox.common.ApiException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * 第308轮：客户端对话线程必须限制整体大小。
 *
 * <p>{@code saveClientThread} 会把整个 {@code threadData} 序列化后写入 TEXT 列，原先没有任何大小
 * 上限：客户端可提交数 MB 的线程数据，造成库膨胀；而 {@code listAllPersistedThreads} 又会把所有
 * 线程 JSON 全量载入内存，进一步放大影响。
 */
@DataJpaTest(
    properties = {
      "spring.datasource.url=jdbc:h2:mem:conversation-thread-limit;MODE=PostgreSQL;DB_CLOSE_DELAY=-1",
      "spring.jpa.hibernate.ddl-auto=create-drop"
    })
@Transactional(propagation = Propagation.NOT_SUPPORTED)
class AiConversationThreadSizeLimitTests {
  @Autowired private AiConversationSessionRepository repository;

  @BeforeEach
  void clear() {
    repository.deleteAll();
  }

  private AiConversationMemoryService service() {
    return new AiConversationMemoryService(
        20, 20, 120, repository, new ObjectMapper(), mock(AiAgentRuntimeClient.class));
  }

  @Test
  void oversizedThreadIsRejectedAndNotPersisted() {
    Map<String, Object> huge = new HashMap<>();
    huge.put("messages", "x".repeat(2_000_000));

    assertThatThrownBy(() -> service().saveClientThread("oversize-thread", huge))
        .as("超过 512000 字符的对话线程必须被拒绝")
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("对话线程内容过大");

    assertThat(repository.findById("oversize-thread")).isEmpty();
  }

  @Test
  void normalThreadIsStillPersisted() {
    Map<String, Object> normal = new HashMap<>();
    normal.put("title", "正常对话");
    normal.put("messages", "hi");
    service().saveClientThread("normal-thread", normal);

    assertThat(repository.findById("normal-thread")).isPresent();
  }
}
