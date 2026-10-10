package com.bachelor.toolbox.project;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.ai.AiAgentRequest;
import com.bachelor.toolbox.ai.AiPlanResponse;
import com.bachelor.toolbox.ai.CrossTurnRecoveryService.RecoveryAnchor;
import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.AuthorizedTargetRepository;
import com.bachelor.toolbox.target.TargetService;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;

@DataJpaTest(properties = {
    "spring.datasource.url=jdbc:h2:mem:approval-idempotency;MODE=PostgreSQL;DB_CLOSE_DELAY=-1;LOCK_TIMEOUT=10000",
    "spring.jpa.hibernate.ddl-auto=create-drop",
    "spring.jpa.show-sql=false"
})
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Import({ProjectApprovalService.class, ProjectAuthorizationService.class})
@Transactional(propagation = Propagation.NOT_SUPPORTED)
class ProjectApprovalIdempotencyTransactionTests {
  @Autowired private ProjectApprovalService service;
  @Autowired private ProjectApprovalRepository approvals;
  @Autowired private AssessmentProjectRepository projects;
  @Autowired private AuthorizedTargetRepository targets;
  @Autowired private PlatformTransactionManager transactions;
  @MockBean private AuditService audit;
  @MockBean private TargetService targetService;
  @MockBean private com.bachelor.toolbox.notification.NotificationService notifications;

  private AssessmentProject project;
  private AuthorizedTarget target;

  @BeforeEach
  void setUp() {
    approvals.deleteAllInBatch();
    targets.deleteAllInBatch();
    projects.deleteAllInBatch();
    clearInvocations(audit);
    project = projects.saveAndFlush(project("owner"));
    target = targets.saveAndFlush(target("http://127.0.0.1:8080"));
    // The service and both repositories use real, independent database transactions.
    // Only the existing target access adapter and audit sink are inert in this fixture.
    when(targetService.lockForAgentExecution(any())).thenAnswer(call ->
        targets.findByIdForUpdate(call.getArgument(0)).orElseThrow());
    authenticate("owner");
  }

  @AfterEach
  void clearAuthentication() {
    SecurityContextHolder.clearContext();
  }

  @Test
  void newlyPendingPlanNotifiesAdministratorsAndRetryDoesNotNotifyAgain() {
    var request = request(project.getId(), target.getId(), "notification-turn");
    var first = service.requestAiPlan(request, plan(Map.of()), null);
    var retry = service.requestAiPlan(request, plan(Map.of()), null);
    assertThat(retry.getId()).isEqualTo(first.getId());
    verify(notifications).publish(org.mockito.ArgumentMatchers.eq("approval:" + first.getId() + ":PENDING"),
        org.mockito.ArgumentMatchers.eq(project.getId()), org.mockito.ArgumentMatchers.eq(true),
        org.mockito.ArgumentMatchers.eq("approval"), org.mockito.ArgumentMatchers.eq("warning"),
        org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.anyString(),
        org.mockito.ArgumentMatchers.eq("/projects/" + project.getId() + "?tab=audits&approvalId=" + first.getId()),
        org.mockito.ArgumentMatchers.eq(List.of()));
    org.mockito.Mockito.verifyNoMoreInteractions(notifications);
  }

  @Test
  void concurrentRetryWaitsForFirstCommitAndReturnsTheSameTicket() throws Exception {
    var executor = Executors.newFixedThreadPool(2);
    var firstInserted = new CountDownLatch(1);
    var secondStarted = new CountDownLatch(1);
    var releaseCommit = new CountDownLatch(1);
    var request = request(project.getId(), target.getId(), "same-turn");
    try {
      var first = executor.submit(() -> {
        authenticate("owner");
        try {
          return new TransactionTemplate(transactions).execute(status -> {
            var saved = service.requestAiPlan(request, plan(Map.of()), null);
            firstInserted.countDown();
            await(releaseCommit);
            return saved.getId();
          });
        } finally {
          SecurityContextHolder.clearContext();
        }
      });
      assertThat(firstInserted.await(5, TimeUnit.SECONDS)).isTrue();
      var second = executor.submit(() -> {
        authenticate("owner");
        secondStarted.countDown();
        try {
          return service.requestAiPlan(request, plan(Map.of()), null).getId();
        } finally {
          SecurityContextHolder.clearContext();
        }
      });
      assertThat(secondStarted.await(5, TimeUnit.SECONDS)).isTrue();
      assertThatThrownBy(() -> second.get(200, TimeUnit.MILLISECONDS))
          .isInstanceOf(java.util.concurrent.TimeoutException.class);
      releaseCommit.countDown();
      Long firstId = first.get(10, TimeUnit.SECONDS);
      assertThat(second.get(10, TimeUnit.SECONDS)).isEqualTo(firstId);
      assertThat(service.requestAiPlan(request, plan(Map.of()), null).getId()).isEqualTo(firstId);
      assertThat(approvals.count()).isEqualTo(1);
      verify(audit, times(1)).record(any(), any(), any(), any(), any(), any(), any());
    } finally {
      releaseCommit.countDown();
      executor.shutdownNow();
      assertThat(executor.awaitTermination(5, TimeUnit.SECONDS)).isTrue();
    }
  }

  @Test
  void rejectedOrApprovedTicketIsReturnedWithoutResettingDecisionOrRecovery() throws Exception {
    for (String status : List.of("REJECTED", "APPROVED")) {
      var request = request(project.getId(), target.getId(), "decided-" + status);
      var originalAnchor = new RecoveryAnchor("run-original", "session", "policy", 1L, "digest");
      var saved = service.requestAiPlan(request, plan(Map.of()), originalAnchor);
      service.decide(project.getId(), saved.getId(), status, "human decision");
      var replay = service.requestAiPlan(request, plan(Map.of()),
          new RecoveryAnchor("run-retry", "session", "policy", 2L, "new-digest"));
      assertThat(replay.getId()).isEqualTo(saved.getId());
      assertThat(replay.getStatus()).isEqualTo(status);
      assertThat(replay.getComment()).isEqualTo("human decision");
      assertThat(replay.getAiRecoveryJson()).contains("run-original").doesNotContain("run-retry");
    }
    assertThat(approvals.count()).isEqualTo(2);
  }

  @Test
  void sameTurnCannotReplacePlanOrRequestOrTarget() {
    var request = request(project.getId(), target.getId(), "conflict");
    var saved = service.requestAiPlan(request, plan(Map.of()), null);
    assertConflict(() -> service.requestAiPlan(request, plan(Map.of("path", "/changed")), null));
    var changedPrompt = new AiAgentRequest(project.getId(), target.getId(), "session", "changed prompt",
        true, null, List.of(), "standard", "conflict");
    assertConflict(() -> service.requestAiPlan(changedPrompt, plan(Map.of()), null));
    var otherTarget = targets.saveAndFlush(target("http://127.0.0.1:8081"));
    assertConflict(() -> service.requestAiPlan(
        request(project.getId(), otherTarget.getId(), "conflict"), plan(Map.of()), null));
    assertThat(approvals.count()).isEqualTo(1);
    assertThat(approvals.findById(saved.getId()).orElseThrow().getAiPlanJson()).isEqualTo(saved.getAiPlanJson());
  }

  @Test
  void sameTurnCannotReuseChangedProjectOrTargetAuthorization() {
    var request = request(project.getId(), target.getId(), "authorization-change");
    service.requestAiPlan(request, plan(Map.of()), null);
    project.setAuthorizationStatement("changed authorization");
    projects.saveAndFlush(project);
    assertConflict(() -> service.requestAiPlan(request, plan(Map.of()), null));
    project.setAuthorizationStatement("authorized fixture");
    projects.saveAndFlush(project);
    target.setAllowedPorts("8081");
    targets.saveAndFlush(target);
    assertConflict(() -> service.requestAiPlan(request, plan(Map.of()), null));
    assertThat(approvals.count()).isEqualTo(1);
  }

  @Test
  void mapKeyOrderDoesNotChangeAnOtherwiseIdenticalPlan() {
    var request = request(project.getId(), target.getId(), "map-order");
    var firstParams = new java.util.LinkedHashMap<String, Object>();
    firstParams.put("path", "/");
    firstParams.put("nested", Map.of("b", 2, "a", 1));
    var secondParams = new java.util.LinkedHashMap<String, Object>();
    secondParams.put("nested", Map.of("a", 1, "b", 2));
    secondParams.put("path", "/");
    var first = service.requestAiPlan(request, plan(firstParams), null);
    assertThat(service.requestAiPlan(request, plan(secondParams), null).getId()).isEqualTo(first.getId());
  }

  @Test
  void keySeparatesProjectsApplicantsAndNewTurns() {
    var first = service.requestAiPlan(request(project.getId(), target.getId(), "scope"), plan(Map.of()), null);
    authenticate("another-admin");
    var second = service.requestAiPlan(request(project.getId(), target.getId(), "scope"), plan(Map.of()), null);
    var otherProject = projects.saveAndFlush(project("another-admin"));
    var third = service.requestAiPlan(request(otherProject.getId(), target.getId(), "scope"), plan(Map.of()), null);
    var fourth = service.requestAiPlan(request(project.getId(), target.getId(), "new-turn"), plan(Map.of()), null);
    assertThat(List.of(first.getAiRequestKey(), second.getAiRequestKey(), third.getAiRequestKey(), fourth.getAiRequestKey()))
        .doesNotHaveDuplicates().allMatch(key -> key.matches("[0-9a-f]{64}"));
    assertThat(approvals.count()).isEqualTo(4);
  }

  @Test
  void databaseUniqueConstraintRejectsDuplicateEvenWithoutServiceLock() {
    var saved = service.requestAiPlan(request(project.getId(), target.getId(), "db-constraint"), plan(Map.of()), null);
    var duplicate = legacyApproval();
    duplicate.setAiRequestKey(saved.getAiRequestKey());
    assertThatThrownBy(() -> approvals.saveAndFlush(duplicate)).isInstanceOf(DataIntegrityViolationException.class);
    assertThat(approvals.count()).isEqualTo(1);
  }

  @Test
  void nullableKeyPreservesMultipleLegacyRowsAndDoesNotLeakInPublicJson() throws Exception {
    var firstLegacy = approvals.saveAndFlush(legacyApproval());
    var secondLegacy = approvals.saveAndFlush(legacyApproval());
    var current = service.requestAiPlan(request(project.getId(), target.getId(), "new-request"), plan(Map.of()), null);
    assertThat(approvals.count()).isEqualTo(3);
    assertThat(approvals.findById(firstLegacy.getId()).orElseThrow().getAiRequestKey()).isNull();
    assertThat(approvals.findById(secondLegacy.getId()).orElseThrow().getAiRequestKey()).isNull();
    assertThat(new ObjectMapper().findAndRegisterModules().writeValueAsString(current))
        .doesNotContain("aiRequestKey", "aiRequestJson", "aiPlanJson", current.getAiRequestKey());
  }

  @Test
  void missingOrInvalidTurnNeverCreatesAnUnkeyedNewApproval() {
    for (String turn : new String[] {null, "", "bad turn"}) {
      assertThatThrownBy(() -> service.requestAiPlan(request(project.getId(), target.getId(), turn), plan(Map.of()), null))
          .isInstanceOf(ApiException.class).hasMessageContaining("Turn ID");
    }
    assertThat(approvals.count()).isZero();
  }

  private ProjectApproval legacyApproval() {
    var approval = new ProjectApproval();
    approval.setProjectId(project.getId());
    approval.setAction("SCAN");
    approval.setStatus("PENDING");
    approval.setRequestedBy("historical-user");
    return approval;
  }

  private static void assertConflict(org.assertj.core.api.ThrowableAssert.ThrowingCallable call) {
    assertThatThrownBy(call).isInstanceOf(ApiException.class).hasMessageContaining("相同 Turn ID");
  }

  private static void authenticate(String name) {
    SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(
        name, null, List.of(new SimpleGrantedAuthority("ROLE_ADMIN"))));
  }

  private static void await(CountDownLatch latch) {
    try {
      if (!latch.await(5, TimeUnit.SECONDS)) throw new AssertionError("Commit barrier timed out");
    } catch (InterruptedException ex) {
      Thread.currentThread().interrupt();
      throw new AssertionError(ex);
    }
  }

  private static AiAgentRequest request(Long projectId, Long targetId, String turnId) {
    return new AiAgentRequest(projectId, targetId, "session", "Inspect authorized fixture", true,
        null, List.of(), "standard", turnId);
  }

  private static AiPlanResponse plan(Map<String, Object> params) {
    return new AiPlanResponse("fixture", "model", "saved original plan", true,
        List.of(new AiPlanResponse.PlanStep("http_headers", "headers", "authorized check", params)));
  }

  private static AssessmentProject project(String owner) {
    var project = new AssessmentProject();
    project.setName("approval transaction fixture");
    project.setOwner(owner);
    project.setAuthorizationStatement("authorized fixture");
    project.setAuthorizationValidFrom(Instant.now().minusSeconds(3600));
    project.setAuthorizationExpiresAt(Instant.now().plusSeconds(3600));
    project.setStatus("ACTIVE");
    return project;
  }

  private static AuthorizedTarget target(String url) {
    var target = new AuthorizedTarget();
    target.setName("approval fixture");
    target.setTargetType("URL");
    target.setTargetValue(url);
    target.setAuthorizationNote("authorized fixture");
    target.setAllowedPorts("8080,8081");
    target.setAuthorizationValidFrom(Instant.now().minusSeconds(3600));
    target.setAuthorizationExpiresAt(Instant.now().plusSeconds(3600));
    return target;
  }
}
