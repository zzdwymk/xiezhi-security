package com.bachelor.toolbox.ai;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@DataJpaTest(
    properties = {
      "spring.datasource.url=jdbc:h2:mem:conversation-memory;MODE=PostgreSQL;DB_CLOSE_DELAY=-1",
      "spring.jpa.hibernate.ddl-auto=create-drop"
    })
@Transactional(propagation = Propagation.NOT_SUPPORTED)
class AiConversationMemoryPersistenceTests {
  @Autowired private AiConversationSessionRepository repository;

  @BeforeEach
  void clearRepository() {
    repository.deleteAll();
  }

  @Test
  void restoresAndClearsConversationUsingTheRealJpaRepository() {
    AiAgentRuntimeClient runtime = mock(AiAgentRuntimeClient.class);
    AiConversationMemoryService first = service(runtime);
    first.open("jpa-restart", 101L, 202L);
    first.addUser("jpa-restart", "question before restart");
    first.addAssistant("jpa-restart", "answer before restart");
    repository.flush();

    AiConversationMemoryService restarted = service(runtime);
    restarted.open("jpa-restart", 101L, 202L);

    assertThat(restarted.transcript("jpa-restart"))
        .contains("question before restart", "answer before restart");
    assertThat(restarted.clear("jpa-restart"))
        .isEqualTo(new AiConversationMemoryService.SessionScope(101L, 202L));
    assertThat(repository.findById("jpa-restart")).isEmpty();
    verify(runtime).clearConversationMemories(101L, "jpa-restart");
  }

  private AiConversationMemoryService service(AiAgentRuntimeClient runtime) {
    return new AiConversationMemoryService(
        20, 20, 120, repository, new ObjectMapper(), runtime);
  }
}
