package com.bachelor.toolbox.ai;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

import com.bachelor.toolbox.audit.AuditLogRepository;
import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.project.AssessmentProject;
import com.bachelor.toolbox.project.AssessmentProjectRepository;
import com.bachelor.toolbox.project.ProjectAuthorizationService;
import com.bachelor.toolbox.project.ProjectTarget;
import com.bachelor.toolbox.project.ProjectTargetRepository;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.AuthorizedTargetRepository;
import com.bachelor.toolbox.task.SecurityTask;
import com.bachelor.toolbox.task.SecurityTaskRepository;
import com.bachelor.toolbox.task.TaskExecutionService;
import com.bachelor.toolbox.task.TaskSnapshotService;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.test.mock.mockito.SpyBean;

@SpringBootTest(
    webEnvironment = SpringBootTest.WebEnvironment.MOCK,
    properties = {
      "spring.datasource.url=jdbc:h2:mem:security-agent-tools-tx;MODE=PostgreSQL;DB_CLOSE_DELAY=-1;LOCK_TIMEOUT=10000",
      "spring.jpa.hibernate.ddl-auto=create-drop",
      "toolbox.ai.api-key=",
      "toolbox.ai.agent.max-active-tasks-per-project=2",
      "toolbox.ai.agent.max-active-tasks-per-target=2",
      "toolbox.auth.admin-password=test-admin-password-7bbbe095d8724fcb",
      "toolbox.auth.jwt-secret=test-jwt-secret-cdc24d415ad843aa9ef313028ae9be30",
      "toolbox.traffic.mitm-ca-password=test-mitm-ca-password-1d6ad9b95b76490e",
      "toolbox.traffic.mitm-enabled=false",
      "toolbox.vulnerability-catalog.nuclei.import-on-startup=false",
      "toolbox.vulnerability-catalog.cisa-kev-enabled=false"
    })
class SecurityAgentToolsTransactionTests {
  @Autowired private SecurityAgentTools tools;
  @Autowired private ProjectAuthorizationService authorization;
  @Autowired private AssessmentProjectRepository projects;
  @Autowired private AuthorizedTargetRepository targets;
  @Autowired private ProjectTargetRepository projectTargets;
  @Autowired private SecurityTaskRepository tasks;
  @Autowired private AiAgentDispatchRepository dispatches;
  @Autowired private AuditLogRepository audits;

  @MockBean private TaskExecutionService taskExecutionService;
  @SpyBean private TaskSnapshotService taskSnapshotService;

  private AssessmentProject project;
  private AuthorizedTarget target;

  @BeforeEach
  void setUp() {
    reset(taskSnapshotService);
    clearInvocations(taskExecutionService);
    dispatches.deleteAllInBatch();
    audits.deleteAllInBatch();
    tasks.deleteAllInBatch();
    projectTargets.deleteAllInBatch();
    targets.deleteAllInBatch();
    projects.deleteAllInBatch();

    Instant now = Instant.now();
    project = new AssessmentProject();
    project.setName("Agent transaction test");
    project.setDescription("Atomic quota and idempotency fixture");
    project.setAuthorizationStatement("Authorized integration test");
    project.setAuthorizationValidFrom(now.minusSeconds(3600));
    project.setAuthorizationExpiresAt(now.plusSeconds(3600));
    project.setStatus("ACTIVE");
    project.setOwner("SYSTEM");
    project = projects.saveAndFlush(project);

    target = new AuthorizedTarget();
    target.setName("Local HTTP target");
    target.setTargetValue("http://127.0.0.1");
    target.setTargetType("URL");
    target.setAuthorizationNote("Authorized integration test target");
    target.setAllowedPorts("80,443");
    target.setEnabled(true);
    target.setAuthorizationValidFrom(now.minusSeconds(3600));
    target.setAuthorizationExpiresAt(now.plusSeconds(3600));
    target = targets.saveAndFlush(target);
    projectTargets.saveAndFlush(new ProjectTarget(project.getId(), target.getId()));
  }

  @Test
  void concurrentPlansCompetingForLastQuotaCreateOnlyOneBatch() throws Exception {
    tasks.saveAndFlush(pendingTask("http_headers"));

    List<Attempt> attempts =
        executeConcurrently(
            List.of(
                new Invocation(request("quota-turn-a"), singleStepPlan()),
                new Invocation(request("quota-turn-b"), singleStepPlan())));

    assertThat(attempts).filteredOn(Attempt::succeeded).hasSize(1);
    assertThat(attempts).filteredOn(attempt -> !attempt.succeeded()).hasSize(1);
    assertThat(attempts)
        .filteredOn(attempt -> !attempt.succeeded())
        .extracting(Attempt::failure)
        .allSatisfy(
            failure -> {
              assertThat(failure).isInstanceOf(ApiException.class);
              assertThat(failure.getMessage()).contains("配额不足");
            });
    assertThat(tasks.count()).isEqualTo(2);
    assertThat(dispatches.count()).isEqualTo(1);
    verify(taskExecutionService, times(1)).executeAsync(anyLong());
  }

  @Test
  void concurrentAndSequentialReplayOfSameTurnCreatesOneBatch() throws Exception {
    AiAgentRequest request = request("same-turn");
    AiPlanResponse plan = singleStepPlan();

    List<Attempt> attempts =
        executeConcurrently(
            List.of(new Invocation(request, plan), new Invocation(request, plan)));

    assertThat(attempts).allMatch(Attempt::succeeded);
    assertThat(attempts.get(0).response().taskIds())
        .isEqualTo(attempts.get(1).response().taskIds());

    AiDispatchResponse sequentialReplay = execute(request, plan);

    assertThat(sequentialReplay.taskIds()).isEqualTo(attempts.get(0).response().taskIds());
    assertThat(tasks.count()).isEqualTo(1);
    assertThat(dispatches.count()).isEqualTo(1);
    verify(taskExecutionService, times(1)).executeAsync(anyLong());
  }

  @Test
  void sameTurnWithDifferentPlanIsRejectedWithoutCreatingAnotherBatch() throws Exception {
    AiAgentRequest request = request("conflicting-turn");
    AiDispatchResponse accepted = execute(request, singleStepPlan());
    AiPlanResponse conflictingPlan =
        new AiPlanResponse(
            "mock-llm",
            "test-model",
            "Different executable plan",
            true,
            List.of(
                new AiPlanResponse.PlanStep(
                    "http_security_check",
                    "CORS check",
                    "Different action under the same turn",
                    Map.of("check", "cors"))));

    assertThatThrownBy(() -> execute(request, conflictingPlan))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("相同 Turn ID");

    assertThat(tasks.count()).isEqualTo(1);
    assertThat(dispatches.count()).isEqualTo(1);
    assertThat(dispatches.findAll().get(0).getTaskIds())
        .isEqualTo(String.valueOf(accepted.taskIds().get(0)));
    verify(taskExecutionService, times(1)).executeAsync(anyLong());
  }

  @Test
  void failureOnSecondTaskRollsBackWholeBatchAndNeverEnqueues() {
    AtomicInteger captures = new AtomicInteger();
    doAnswer(
            invocation -> {
              if (captures.incrementAndGet() == 2) {
                throw new ApiException("Injected second task failure");
              }
              return invocation.callRealMethod();
            })
        .when(taskSnapshotService)
        .capture(any(), any(), any());

    AiPlanResponse twoStepPlan =
        new AiPlanResponse(
            "mock-llm",
            "test-model",
            "Two-task atomic batch",
            true,
            List.of(
                new AiPlanResponse.PlanStep(
                    "http_headers", "Headers", "Inspect response headers", Map.of()),
                new AiPlanResponse.PlanStep(
                    "http_security_check",
                    "Cookie policy",
                    "Inspect cookie attributes",
                    Map.of("check", "cookies"))));

    assertThatThrownBy(() -> execute(request("rollback-turn"), twoStepPlan))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("Injected second task failure");

    assertThat(captures).hasValue(2);
    assertThat(tasks.count()).isZero();
    assertThat(dispatches.count()).isZero();
    assertThat(audits.count()).isZero();
    verifyNoInteractions(taskExecutionService);
  }

  private AiDispatchResponse execute(AiAgentRequest request, AiPlanResponse plan) throws Exception {
    return authorization.callWithSystemAccess(() -> tools.executeAuthorizedPlan(request, plan));
  }

  private List<Attempt> executeConcurrently(List<Invocation> invocations) throws Exception {
    ExecutorService executor = Executors.newFixedThreadPool(invocations.size());
    CountDownLatch ready = new CountDownLatch(invocations.size());
    CountDownLatch start = new CountDownLatch(1);
    try {
      List<Future<Attempt>> futures = new ArrayList<>();
      for (Invocation invocation : invocations) {
        Callable<Attempt> call =
            () -> {
              ready.countDown();
              if (!start.await(5, TimeUnit.SECONDS)) {
                return Attempt.failure(new AssertionError("Concurrent start barrier timed out"));
              }
              try {
                return Attempt.success(execute(invocation.request(), invocation.plan()));
              } catch (Throwable failure) {
                return Attempt.failure(failure);
              }
            };
        futures.add(executor.submit(call));
      }
      assertThat(ready.await(5, TimeUnit.SECONDS)).isTrue();
      start.countDown();
      List<Attempt> attempts = new ArrayList<>();
      for (Future<Attempt> future : futures) {
        attempts.add(future.get(15, TimeUnit.SECONDS));
      }
      return List.copyOf(attempts);
    } finally {
      start.countDown();
      executor.shutdownNow();
      assertThat(executor.awaitTermination(5, TimeUnit.SECONDS)).isTrue();
    }
  }

  private AiAgentRequest request(String turnId) {
    return new AiAgentRequest(
        project.getId(),
        target.getId(),
        "tx-session",
        "Inspect the authorized local HTTP target",
        true,
        null,
        List.of(),
        "standard",
        turnId);
  }

  private AiPlanResponse singleStepPlan() {
    return new AiPlanResponse(
        "mock-llm",
        "test-model",
        "One safe task",
        true,
        List.of(
            new AiPlanResponse.PlanStep(
                "http_headers", "Headers", "Inspect response headers", Map.of())));
  }

  private SecurityTask pendingTask(String toolCode) {
    SecurityTask task = new SecurityTask();
    task.setProjectId(project.getId());
    task.setTargetId(target.getId());
    task.setToolCode(toolCode);
    task.setStatus("PENDING");
    task.setProgress(0);
    task.setRequestJson("{}");
    return task;
  }

  private record Invocation(AiAgentRequest request, AiPlanResponse plan) {}

  private record Attempt(AiDispatchResponse response, Throwable failure) {
    static Attempt success(AiDispatchResponse response) {
      return new Attempt(response, null);
    }

    static Attempt failure(Throwable failure) {
      return new Attempt(null, failure);
    }

    boolean succeeded() {
      return response != null;
    }
  }
}
