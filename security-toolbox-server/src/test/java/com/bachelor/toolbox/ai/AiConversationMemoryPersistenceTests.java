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

  @Test
  void deliveredPlanAndOriginalMessagesSurviveRealJpaRestart() {
    var first = service(mock(AiAgentRuntimeClient.class));
    var fixture = new AiPlanContinuityServiceTests.Fixture(first);
    first.addUser("session", "keep user text");
    first.addAssistant("session", "keep assistant text");
    fixture.deliver(AiPlanContinuityServiceTests.plan("service"));
    repository.flush();
    String snapshot = repository.findById("session").orElseThrow().getLastPlanJson();
    var restarted = service(mock(AiAgentRuntimeClient.class));
    var restored = new AiPlanContinuityServiceTests.Fixture(restarted);
    assertThat(restored.service.plannerContext(restored.open())).contains("service", "80,443");
    assertThat(restarted.transcript("session")).contains("keep user text", "keep assistant text");
    assertThat(repository.findById("session").orElseThrow().getLastPlanJson()).isEqualTo(snapshot);
    org.assertj.core.api.Assertions.assertThatThrownBy(() -> restored.service.prepare(
        AiPlanContinuityServiceTests.request(true), "session", AiPlanContinuityServiceTests.plan("quick"), restored.open()))
        .isInstanceOf(AiPlanContinuityService.PlanChangedException.class);
    assertThat(repository.findById("session").orElseThrow().getLastPlanJson()).isEqualTo(snapshot);
  }

  @Test
  void pendingDeliverySurvivesJpaRestartAndRequiresNewConversationWithoutDeletingOriginal() {
    var first = service(mock(AiAgentRuntimeClient.class));
    var fixture = new AiPlanContinuityServiceTests.Fixture(first);
    first.addUser("session", "original retained question");
    fixture.deliver(AiPlanContinuityServiceTests.plan("service"));
    var candidate = fixture.service.prepare(AiPlanContinuityServiceTests.request(false), "session",
        AiPlanContinuityServiceTests.plan("service"), fixture.open());
    fixture.service.stage(candidate); // Represents crash/disconnect/promotion write failure after staging.
    repository.flush();
    var restarted = service(mock(AiAgentRuntimeClient.class));
    var restored = new AiPlanContinuityServiceTests.Fixture(restarted);
    assertThat(restored.open().deliveryPending()).isTrue();
    assertThat(restored.open().previous().plan().steps().get(0).parameters()).containsEntry("mode", "service");
    org.assertj.core.api.Assertions.assertThatThrownBy(() -> restored.service.prepare(
        AiPlanContinuityServiceTests.request(true), "session", AiPlanContinuityServiceTests.plan("quick"), restored.open()))
        .isInstanceOf(AiPlanContinuityService.PlanDeliveryPendingException.class);
    org.assertj.core.api.Assertions.assertThatThrownBy(() -> restored.deliver(AiPlanContinuityServiceTests.plan("service")))
        .isInstanceOf(AiPlanContinuityService.PlanDeliveryPendingException.class);
    restarted.open("replacement", 5L, 8L);
    var newRequest = new AiAgentRequest(5L, 8L, "replacement", "重新规划192.168.136.132", false,
        null, java.util.List.of(), "standard", "replacement-turn", "workflow", 1L, "sha256:" + "a".repeat(64));
    var replacement = restored.service.prepare(newRequest, "replacement", AiPlanContinuityServiceTests.plan("quick"),
        restored.service.open(newRequest, "replacement"));
    restored.service.stage(replacement);
    restored.service.delivered(replacement);
    assertThat(restored.open().deliveryPending()).isTrue();
    assertThat(restored.service.open(newRequest, "replacement").previous().plan().steps().get(0).parameters())
        .containsEntry("mode", "quick");
    assertThat(restarted.transcript("session")).contains("original retained question");
    assertThat(repository.findById("session")).isPresent();
  }
}
