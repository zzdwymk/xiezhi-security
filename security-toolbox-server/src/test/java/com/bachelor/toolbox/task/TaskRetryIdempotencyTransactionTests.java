package com.bachelor.toolbox.task;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.project.AssessmentProject;
import com.bachelor.toolbox.project.AssessmentProjectRepository;
import com.bachelor.toolbox.project.AssessmentProjectService;
import com.bachelor.toolbox.project.ProjectAuthorizationService;
import com.bachelor.toolbox.project.ProjectTarget;
import com.bachelor.toolbox.project.ProjectTargetRepository;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.AuthorizedTargetRepository;
import com.bachelor.toolbox.target.PortRangeParser;
import com.bachelor.toolbox.target.TargetService;
import com.bachelor.toolbox.tool.SecurityTool;
import com.bachelor.toolbox.tool.SecurityToolRegistry;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.util.List;
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

@DataJpaTest(showSql = false, properties = {
    "spring.datasource.url=jdbc:h2:mem:task-retry-idempotency;MODE=PostgreSQL;DB_CLOSE_DELAY=-1;LOCK_TIMEOUT=10000",
    "spring.jpa.hibernate.ddl-auto=create-drop"
})
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Import({TaskService.class, ProjectAuthorizationService.class, AssessmentProjectService.class,
    TargetService.class, PortRangeParser.class, ObjectMapper.class})
@Transactional(propagation = Propagation.NOT_SUPPORTED)
class TaskRetryIdempotencyTransactionTests {
  @Autowired private TaskService service;
  @Autowired private SecurityTaskRepository tasks;
  @Autowired private AssessmentProjectRepository projects;
  @Autowired private AuthorizedTargetRepository targets;
  @Autowired private ProjectTargetRepository links;
  @Autowired private PlatformTransactionManager transactions;
  @jakarta.persistence.PersistenceContext private jakarta.persistence.EntityManager entityManager;
  @MockBean private AuditService audit;
  @MockBean private TaskExecutionService execution;
  @MockBean private TaskExecutionControlService executionControl;
  @MockBean private TaskProgressEventService progressEvents;
  @MockBean private TaskSnapshotService snapshots;
  @MockBean private SecurityToolRegistry registry;

  private AssessmentProject project;
  private AuthorizedTarget target;
  private SecurityTask original;

  @BeforeEach
  void setUp() {
    tasks.deleteAllInBatch();
    links.deleteAllInBatch();
    targets.deleteAllInBatch();
    projects.deleteAllInBatch();
    reset(execution, audit, snapshots);
    when(registry.require(any())).thenReturn(mock(SecurityTool.class));
    project = new AssessmentProject();
    project.setName("retry transaction fixture");
    project.setOwner("owner");
    project.setAuthorizationStatement("authorized fixture");
    project.setAuthorizationValidFrom(Instant.now().minusSeconds(3600));
    project.setAuthorizationExpiresAt(Instant.now().plusSeconds(3600));
    project.setStatus("ACTIVE");
    project = projects.saveAndFlush(project);
    target = new AuthorizedTarget();
    target.setName("retry fixture");
    target.setTargetType("URL");
    target.setTargetValue("http://127.0.0.1:8080");
    target.setAuthorizationNote("authorized fixture");
    target.setAllowedPorts("8080");
    target.setAuthorizationValidFrom(Instant.now().minusSeconds(3600));
    target.setAuthorizationExpiresAt(Instant.now().plusSeconds(3600));
    target = targets.saveAndFlush(target);
    links.saveAndFlush(new ProjectTarget(project.getId(), target.getId()));
    original = tasks.saveAndFlush(failedTask());
    authenticate("owner", "ROLE_USER");
  }

  @AfterEach
  void clearSecurity() {
    SecurityContextHolder.clearContext();
  }

  @Test
  void concurrentAndSequentialReplayCreatesAndQueuesOnlyOneRetry() throws Exception {
    var executor = Executors.newFixedThreadPool(2);
    var inserted = new CountDownLatch(1);
    var secondStarted = new CountDownLatch(1);
    var commit = new CountDownLatch(1);
    try {
      var first = executor.submit(() -> {
        authenticate("owner", "ROLE_USER");
        try {
          return new TransactionTemplate(transactions).execute(status -> {
            Long id = service.retry(original.getId(), "network-retry").getId();
            inserted.countDown();
            await(commit);
            return id;
          });
        } finally { SecurityContextHolder.clearContext(); }
      });
      assertThat(inserted.await(5, TimeUnit.SECONDS)).isTrue();
      var second = executor.submit(() -> {
        authenticate("owner", "ROLE_USER");
        try {
          return new TransactionTemplate(transactions).execute(status -> {
            secondStarted.countDown();
            return service.retry(original.getId(), "network-retry").getId();
          });
        } finally { SecurityContextHolder.clearContext(); }
      });
      assertThat(secondStarted.await(5, TimeUnit.SECONDS)).isTrue();
      assertThatThrownBy(() -> second.get(200, TimeUnit.MILLISECONDS))
          .isInstanceOf(java.util.concurrent.TimeoutException.class);
      verifyNoInteractions(execution);
      commit.countDown();
      Long id = first.get(10, TimeUnit.SECONDS);
      assertThat(second.get(10, TimeUnit.SECONDS)).isEqualTo(id);
      assertThat(service.retry(original.getId(), "network-retry").getId()).isEqualTo(id);
      assertThat(tasks.count()).isEqualTo(2);
      verify(execution, times(1)).executeAsync(id);
      verify(snapshots, times(1)).capture(any(), any(), any());
      verify(audit, times(1)).record(any(), any(), any(), any(), any());
    } finally {
      commit.countDown();
      executor.shutdownNow();
      assertThat(executor.awaitTermination(5, TimeUnit.SECONDS)).isTrue();
    }
  }

  @Test
  void differentKeysTasksAndOperatorsRemainSeparateOperations() {
    var first = service.retry(original.getId(), "key");
    var second = service.retry(original.getId(), "another-key");
    authenticate("another-admin", "ROLE_ADMIN");
    var third = service.retry(original.getId(), "key");
    var other = tasks.saveAndFlush(failedTask());
    var fourth = service.retry(other.getId(), "key");
    assertThat(List.of(first.getId(), second.getId(), third.getId(), fourth.getId())).doesNotHaveDuplicates();
    assertThat(List.of(first.getRetryRequestKey(), second.getRetryRequestKey(), third.getRetryRequestKey(), fourth.getRetryRequestKey()))
        .doesNotHaveDuplicates().allMatch(key -> key.matches("[0-9a-f]{64}"));
    verify(execution, times(4)).executeAsync(anyLong());
  }

  @Test
  void legacyNoKeyCallsStillCreateSeparateManualRetries() {
    var first = service.retry(original.getId());
    var second = service.retry(original.getId());
    assertThat(first.getId()).isNotEqualTo(second.getId());
    assertThat(first.getRetryRequestKey()).isNull();
    assertThat(second.getRetryRequestKey()).isNull();
    assertThat(tasks.findById(original.getId()).orElseThrow().getStatus()).isEqualTo("FAILED");
    verify(execution, times(2)).executeAsync(anyLong());
  }

  @Test
  void replayRechecksCurrentTargetAuthorizationAndProjectAccess() {
    service.retry(original.getId(), "check-auth");
    clearInvocations(execution);
    target.setAuthorizationExpiresAt(Instant.now().minusSeconds(1));
    targets.saveAndFlush(target);
    assertThatThrownBy(() -> service.retry(original.getId(), "check-auth"))
        .isInstanceOf(ApiException.class).hasMessageContaining("目标授权已过期");
    target.setAuthorizationExpiresAt(Instant.now().plusSeconds(3600));
    targets.saveAndFlush(target);
    project.setOwner("different-owner");
    projects.saveAndFlush(project);
    assertThatThrownBy(() -> service.retry(original.getId(), "check-auth"))
        .isInstanceOf(ApiException.class).hasMessageContaining("无权访问");
    verifyNoInteractions(execution);
    assertThat(tasks.count()).isEqualTo(2);
  }

  @Test
  void replayRechecksProjectTargetMembership() {
    service.retry(original.getId(), "membership");
    new TransactionTemplate(transactions).executeWithoutResult(status ->
        links.deleteByProjectIdAndTargetId(project.getId(), target.getId()));
    assertThatThrownBy(() -> service.retry(original.getId(), "membership"))
        .isInstanceOf(ApiException.class).hasMessageContaining("无权访问该授权目标");
    assertThat(tasks.count()).isEqualTo(2);
  }

  @Test
  void waitingRetryCannotUseProjectAccessLoadedBeforeConcurrentRevocation() throws Exception {
    var executor = Executors.newFixedThreadPool(2);
    var locked = new CountDownLatch(1);
    var release = new CountDownLatch(1);
    var retryStarted = new CountDownLatch(1);
    try {
      var holder = executor.submit(() -> new TransactionTemplate(transactions).execute(status -> {
        entityManager.lock(tasks.findById(original.getId()).orElseThrow(), jakarta.persistence.LockModeType.PESSIMISTIC_WRITE);
        locked.countDown();
        await(release);
        return null;
      }));
      assertThat(locked.await(5, TimeUnit.SECONDS)).isTrue();
      var retry = executor.submit(() -> {
        authenticate("owner", "ROLE_USER");
        retryStarted.countDown();
        try {
          return service.retry(original.getId(), "concurrent-revocation");
        } finally { SecurityContextHolder.clearContext(); }
      });
      assertThat(retryStarted.await(5, TimeUnit.SECONDS)).isTrue();
      assertThatThrownBy(() -> retry.get(200, TimeUnit.MILLISECONDS))
          .isInstanceOf(java.util.concurrent.TimeoutException.class);
      project.setOwner("revoked-owner");
      projects.saveAndFlush(project);
      release.countDown();
      holder.get(10, TimeUnit.SECONDS);
      assertThatThrownBy(() -> retry.get(10, TimeUnit.SECONDS))
          .hasCauseInstanceOf(ApiException.class).hasRootCauseMessage("无权访问该评估项目");
      assertThat(tasks.count()).isEqualTo(1);
      verifyNoInteractions(execution);
    } finally {
      release.countDown();
      executor.shutdownNow();
      assertThat(executor.awaitTermination(5, TimeUnit.SECONDS)).isTrue();
    }
  }

  @Test
  void sameKeyRejectsChangedOriginalParameters() {
    var first = service.retry(original.getId(), "same-key");
    original.setRequestJson("{\"ports\":\"8081\"}");
    tasks.saveAndFlush(original);
    assertThatThrownBy(() -> service.retry(original.getId(), "same-key"))
        .isInstanceOf(ApiException.class).hasMessageContaining("执行范围已变化");
    assertThat(tasks.findById(first.getId()).orElseThrow().getRequestJson()).isEqualTo("{\"ports\":\"8080\"}");
    verify(execution, times(1)).executeAsync(anyLong());
  }

  @Test
  void workflowRetryCannotDiscardDependenciesOrReuseOriginalApproval() {
    original.setWorkflowDigest("sha256:" + "a".repeat(64));
    original.setWorkflowApprovalRequired(true);
    original.setDependencyTaskIds("[123]");
    tasks.saveAndFlush(original);
    assertThatThrownBy(() -> service.retry(original.getId(), "workflow"))
        .isInstanceOf(ApiException.class).hasMessageContaining("重新提交原方案并确认");
    assertThatThrownBy(() -> service.retry(original.getId()))
        .isInstanceOf(ApiException.class).hasMessageContaining("不能以普通重试");
    assertThat(tasks.count()).isEqualTo(1);
    verifyNoInteractions(execution, snapshots);
  }

  @Test
  void queueRejectionIsCommittedAndReplayDoesNotEnqueueAgain() {
    doThrow(new RuntimeException("queue full")).when(execution).executeAsync(anyLong());
    var first = service.retry(original.getId(), "full-queue");
    assertThat(tasks.findById(first.getId()).orElseThrow().getStatus()).isEqualTo("REJECTED");
    var replay = service.retry(original.getId(), "full-queue");
    assertThat(replay.getId()).isEqualTo(first.getId());
    assertThat(replay.getStatus()).isEqualTo("REJECTED");
    verify(execution, times(1)).executeAsync(anyLong());
  }

  @Test
  void rollbackDoesNotLeaveAReceiptOrQueueWorkAndAllowsSameKeyRetry() {
    doThrow(new ApiException("audit failure")).when(audit).record(any(), any(), any(), any(), any());
    assertThatThrownBy(() -> service.retry(original.getId(), "rolled-back"))
        .hasMessageContaining("audit failure");
    assertThat(tasks.count()).isEqualTo(1);
    verifyNoInteractions(execution);
    reset(audit);
    var retry = service.retry(original.getId(), "rolled-back");
    assertThat(tasks.count()).isEqualTo(2);
    verify(execution).executeAsync(retry.getId());
  }

  @Test
  void databaseEnforcesUniquenessWhileLegacyNullKeysAndJsonRemainCompatible() throws Exception {
    var retry = service.retry(original.getId(), "db-key");
    var duplicate = failedTask();
    duplicate.setRetryRequestKey(retry.getRetryRequestKey());
    assertThatThrownBy(() -> tasks.saveAndFlush(duplicate)).isInstanceOf(DataIntegrityViolationException.class);
    tasks.saveAndFlush(failedTask());
    assertThat(tasks.count()).isEqualTo(3);
    assertThat(new ObjectMapper().findAndRegisterModules().writeValueAsString(retry))
        .doesNotContain("retryRequestKey", retry.getRetryRequestKey());
  }

  @Test
  void invalidKeyAndAnonymousRequestCreateNoTask() {
    for (String key : List.of("", "has spaces", "x".repeat(129))) {
      assertThatThrownBy(() -> service.retry(original.getId(), key))
          .isInstanceOf(ApiException.class).hasMessageContaining("Idempotency-Key");
    }
    SecurityContextHolder.clearContext();
    assertThatThrownBy(() -> service.retry(original.getId(), "anonymous"))
        .isInstanceOf(ApiException.class).hasMessageContaining("请先登录");
    assertThat(tasks.count()).isEqualTo(1);
    verifyNoInteractions(execution);
  }

  private SecurityTask failedTask() {
    var task = new SecurityTask();
    task.setProjectId(project.getId());
    task.setTargetId(target.getId());
    task.setToolCode("tcp_ports");
    task.setStatus("FAILED");
    task.setProgress(100);
    task.setRequestJson("{\"ports\":\"8080\"}");
    return task;
  }

  private static void authenticate(String name, String role) {
    SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(
        name, null, List.of(new SimpleGrantedAuthority(role))));
  }

  private static void await(CountDownLatch latch) {
    try {
      if (!latch.await(5, TimeUnit.SECONDS)) throw new AssertionError("Commit barrier timed out");
    } catch (InterruptedException ex) {
      Thread.currentThread().interrupt();
      throw new AssertionError(ex);
    }
  }
}
