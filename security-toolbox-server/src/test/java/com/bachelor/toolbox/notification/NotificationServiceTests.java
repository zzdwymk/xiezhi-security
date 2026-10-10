package com.bachelor.toolbox.notification;

import static org.assertj.core.api.Assertions.assertThat;

import com.bachelor.toolbox.project.AssessmentProject;
import com.bachelor.toolbox.project.AssessmentProjectRepository;
import com.bachelor.toolbox.project.ProjectAuthorizationService;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;

@DataJpaTest(showSql = false, properties = "spring.jpa.hibernate.ddl-auto=create-drop")
@Import({NotificationService.class, ProjectAuthorizationService.class})
@Transactional(propagation = Propagation.NOT_SUPPORTED)
class NotificationServiceTests {
  @Autowired private NotificationService service;
  @Autowired private NotificationRepository repository;
  @Autowired private AssessmentProjectRepository projects;
  @Autowired private com.bachelor.toolbox.finding.FindingRepository findings;
  @Autowired private PlatformTransactionManager transactions;

  @BeforeEach void setUp() {
    repository.deleteAllInBatch();
    findings.deleteAllInBatch();
    projects.deleteAllInBatch();
    authenticate("admin", "ADMIN");
  }

  @AfterEach void clearAuthentication() { SecurityContextHolder.clearContext(); }

  @Test void initialBoundaryDoesNotReplayExistingEventsAndReconnectPaginates() {
    publish("old", null, false);
    var initial = service.feed(null, 100);
    assertThat(initial.items()).isEmpty();
    publish("new-1", null, false);
    publish("new-2", null, false);
    var first = service.feed(initial.cursor(), 1);
    assertThat(first.items()).extracting(NotificationService.Item::eventKey).containsExactly("new-1");
    var second = service.feed(first.cursor(), 1);
    assertThat(second.items()).extracting(NotificationService.Item::eventKey).containsExactly("new-2");
    assertThat(service.feed(second.cursor(), 100).items()).isEmpty();
  }

  @Test void permissionsFilterOwnedProjectsAndAdministratorOnlyEventsWithoutStallingCursor() {
    Long owned = project("alice");
    Long foreign = project("bob");
    publish("owned", owned, false);
    publish("foreign", foreign, false);
    publish("approval", owned, true);
    publish("system", null, true);
    authenticate("alice", "USER");
    var visible = service.feed(0L, 100);
    assertThat(visible.items()).extracting(NotificationService.Item::eventKey).containsExactly("owned");
    assertThat(visible.cursor()).isEqualTo(repository.currentCursor());
    authenticate("admin", "ADMIN");
    assertThat(service.feed(0L, 100).items()).hasSize(4);
  }

  @Test void onlyCommittedBusinessEventsBecomeReadable() {
    var transaction = new TransactionTemplate(transactions);
    transaction.executeWithoutResult(status -> {
      publish("rolled-back", null, false);
      assertThat(repository.count()).isZero();
      status.setRollbackOnly();
    });
    assertThat(repository.count()).isZero();
    transaction.executeWithoutResult(status -> {
      publish("committed", null, false);
      assertThat(repository.count()).isZero();
    });
    assertThat(service.feed(0L, 100).items()).extracting(NotificationService.Item::eventKey)
        .containsExactly("committed");
  }

  @Test void duplicateTerminalEventsAcrossConcurrentWorkersAreDurablyDeduplicated() throws Exception {
    var executor = Executors.newFixedThreadPool(4);
    try {
      var futures = java.util.stream.IntStream.range(0, 8)
          .mapToObj(index -> executor.submit(() -> publish("task:1:SUCCESS", null, false))).toList();
      for (var future : futures) future.get(10, TimeUnit.SECONDS);
    } finally { executor.shutdownNow(); }
    assertThat(repository.count()).isEqualTo(1);
    publish("task:1:SUCCESS", null, false);
    assertThat(repository.count()).isEqualTo(1);
  }

  @Test void publicationFromAnExistingAfterCommitCallbackIsNotLost() {
    new TransactionTemplate(transactions).executeWithoutResult(status ->
        org.springframework.transaction.support.TransactionSynchronizationManager.registerSynchronization(
            new org.springframework.transaction.support.TransactionSynchronization() {
              @Override public void afterCommit() { publish("queued-after-commit", null, false); }
            }));
    assertThat(service.feed(0L, 100).items()).extracting(NotificationService.Item::eventKey)
        .containsExactly("queued-after-commit");
  }

  @Test void severityComesFromPersistedFindingsEvenWithoutResultJson() {
    saveFinding(101L, "HIGH");
    saveFinding(102L, "LOW");
    saveFinding(103L, "CRITICAL");
    assertThat(service.findingSeverities(List.of(101L, 102L))).containsExactly("HIGH", "LOW");
    var task = new com.bachelor.toolbox.task.SecurityTask();
    task.setId(101L);
    task.setProjectId(project("admin"));
    task.setToolCode("nuclei_scan");
    task.setStatus("FAILED");
    new TaskNotificationPublisher(service).publish(task);
    var event = service.feed(0L, 100).items().get(0);
    assertThat(event.outcome()).isEqualTo("error");
    assertThat(event.severities()).containsExactly("HIGH");
  }

  private void saveFinding(Long taskId, String severity) {
    var finding = new com.bachelor.toolbox.finding.Finding();
    finding.setTaskId(taskId);
    finding.setTargetId(1L);
    finding.setTitle("persisted finding");
    finding.setSeverity(severity);
    finding.setSourceTool("nuclei_scan");
    findings.saveAndFlush(finding);
  }

  private void publish(String key, Long projectId, boolean adminOnly) {
    service.publish(key, projectId, adminOnly, "task", "success", "完成", "已保存", "/tasks?taskId=1",
        List.of("HIGH", "HIGH", "low"));
  }

  private Long project(String owner) {
    AssessmentProject project = new AssessmentProject();
    project.setName(owner + " project");
    project.setOwner(owner);
    project.setAuthorizationStatement("test authorization");
    project.setAuthorizationValidFrom(Instant.now().minusSeconds(60));
    project.setAuthorizationExpiresAt(Instant.now().plusSeconds(600));
    return projects.saveAndFlush(project).getId();
  }

  private void authenticate(String name, String role) {
    SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(
        name, "", List.of(new SimpleGrantedAuthority("ROLE_" + role))));
  }
}
