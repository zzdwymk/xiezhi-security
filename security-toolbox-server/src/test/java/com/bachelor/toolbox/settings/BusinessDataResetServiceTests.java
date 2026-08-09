package com.bachelor.toolbox.settings;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.ai.AgentWorkflowSpec;
import com.bachelor.toolbox.ai.AgentWorkflowSpecRepository;
import com.bachelor.toolbox.ai.AiAgentRuntimeClient;
import com.bachelor.toolbox.ai.AiConversationMemoryService;
import com.bachelor.toolbox.audit.AuditLog;
import com.bachelor.toolbox.audit.AuditLogRepository;
import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.auth.User;
import com.bachelor.toolbox.auth.UserRepository;
import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.project.AssessmentProject;
import com.bachelor.toolbox.project.AssessmentProjectRepository;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.AuthorizedTargetRepository;
import com.bachelor.toolbox.task.SecurityTask;
import com.bachelor.toolbox.task.SecurityTaskRepository;
import com.bachelor.toolbox.traffic.TrafficCaptureFilter;
import com.bachelor.toolbox.traffic.TrafficCaptureFilterRepository;
import com.bachelor.toolbox.traffic.TrafficProxyService;
import com.bachelor.toolbox.traffic.TrafficSession;
import com.bachelor.toolbox.traffic.TrafficSessionRepository;
import jakarta.persistence.EntityManager;
import java.time.Instant;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@DataJpaTest(
    properties = {
      "spring.jpa.hibernate.ddl-auto=create-drop",
      "spring.datasource.url=jdbc:h2:mem:business-reset;MODE=PostgreSQL"
    })
class BusinessDataResetServiceTests {
  @Autowired private EntityManager entityManager;
  @Autowired private PlatformTransactionManager transactionManager;
  @Autowired private SecurityTaskRepository tasks;
  @Autowired private AssessmentProjectRepository projects;
  @Autowired private AuthorizedTargetRepository targets;
  @Autowired private UserRepository users;
  @Autowired private AgentWorkflowSpecRepository workflowSpecs;
  @Autowired private TrafficCaptureFilterRepository trafficFilters;
  @Autowired private TrafficSessionRepository trafficSessions;
  @Autowired private AuditLogRepository audits;

  private TrafficProxyService trafficProxy;
  private AiAgentRuntimeClient runtime;
  private AiConversationMemoryService conversations;
  private BusinessDataResetService service;

  @BeforeEach
  void setUp() {
    trafficProxy = mock(TrafficProxyService.class);
    runtime = mock(AiAgentRuntimeClient.class);
    conversations = mock(AiConversationMemoryService.class);
    when(trafficProxy.status()).thenReturn(proxyStatus(false));
    service =
        new BusinessDataResetService(
            entityManager,
            tasks,
            projects,
            trafficProxy,
            trafficSessions,
            runtime,
            conversations,
            new AuditService(audits),
            transactionManager);
  }

  @Test
  void clearsBusinessRowsButPreservesAuthenticationAndSystemConfiguration() {
    User admin = new User();
    admin.setUsername("admin");
    admin.setPasswordHash("hash");
    admin.setRole("ADMIN");
    users.save(admin);

   AgentWorkflowSpec workflow = new AgentWorkflowSpec();
   workflow.setSpecJson("{}");
   workflow.setUpdatedAt(Instant.now());
    workflow.setWorkflowId("test-workflow");
    workflow.setScopeId(1L);
    workflow.setRevision(1L);
    workflow.setSpecDigest("sha256:" + "0".repeat(64));
    workflow.setUpdatedBy("admin");
   workflowSpecs.save(workflow);

    TrafficCaptureFilter filter = new TrafficCaptureFilter();
    filter.setType("HOST");
    filter.setPattern("example.test");
    trafficFilters.save(filter);

    AssessmentProject project = projects.save(project());
    AuthorizedTarget target = targets.save(target());
    tasks.save(task(project.getId(), target.getId(), "SUCCESS"));
    audits.save(audit("OLD_EVENT"));
    when(runtime.clearProjectIndex(project.getId())).thenReturn(3);
    entityManager.flush();

    BusinessDataResetService.ResetResult result = service.clear("CLEAR");

    assertThat(result.deletedRecords()).isEqualTo(4);
    assertThat(result.clearedProjects()).isEqualTo(1);
    assertThat(result.runtimeDocumentsDeleted()).isEqualTo(3);
    assertThat(result.auditLogRetained()).isTrue();
    assertThat(projects.count()).isZero();
    assertThat(targets.count()).isZero();
    assertThat(tasks.count()).isZero();
    assertThat(users.count()).isEqualTo(1);
    assertThat(workflowSpecs.count()).isEqualTo(1);
    assertThat(trafficFilters.count()).isEqualTo(1);
    assertThat(audits.findAll()).singleElement().extracting(AuditLog::getAction)
        .isEqualTo("CLEAR_BUSINESS_DATA");
    verify(runtime).clearProjectIndex(project.getId());
    verify(conversations).evictAllLocal();
  }

  @Test
  void rejectsResetWhileTaskIsPending() {
    AssessmentProject project = projects.save(project());
    AuthorizedTarget target = targets.save(target());
    tasks.save(task(project.getId(), target.getId(), "PENDING"));
    entityManager.flush();

    assertThatThrownBy(() -> service.clear("CLEAR"))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("任务");

    assertThat(projects.count()).isEqualTo(1);
    verify(runtime, never()).clearProjectIndex(project.getId());
  }

  @Test
  void rejectsResetWhileTrafficProxyIsRunning() {
    when(trafficProxy.status()).thenReturn(proxyStatus(true));

    assertThatThrownBy(() -> service.clear("CLEAR"))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("流量代理");
    verify(runtime, never()).clearProjectIndex(org.mockito.ArgumentMatchers.anyLong());
  }

  @Test
  void rejectsResetWhenAStartingTrafficSessionIsStillPersisted() {
    TrafficSession session = new TrafficSession();
    session.setTargetId(1L);
    session.setName("启动中会话");
    session.setStatus("STARTING");
    session.setListenPort(19080);
    session.setHandlingMode("ASK");
    trafficSessions.save(session);
    entityManager.flush();

    assertThatThrownBy(() -> service.clear("CLEAR"))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("流量代理");

    assertThat(trafficSessions.count()).isEqualTo(1);
    verify(runtime, never()).clearProjectIndex(org.mockito.ArgumentMatchers.anyLong());
  }

  @Test
  void keepsDatabaseRowsWhenEnabledRuntimeCannotClearAProjectIndex() {
    AssessmentProject project = projects.save(project());
    entityManager.flush();
    when(runtime.clearProjectIndex(project.getId()))
        .thenThrow(new AiAgentRuntimeClient.RuntimeUnavailableException("runtime down"));

    assertThatThrownBy(() -> service.clear("CLEAR"))
        .isInstanceOf(AiAgentRuntimeClient.RuntimeUnavailableException.class);

    assertThat(projects.count()).isEqualTo(1);
    assertThat(audits.count()).isZero();
    verify(conversations, never()).evictAllLocal();
  }

  @Test
  @Transactional(propagation = Propagation.NOT_SUPPORTED)
  @DirtiesContext(methodMode = DirtiesContext.MethodMode.AFTER_METHOD)
  void rollsBackEveryDatabaseDeleteWhenTheFinalAuditCannotBeStored() {
    AssessmentProject project = projects.save(project());
    AuditService failingAudit = mock(AuditService.class);
    org.mockito.Mockito.doThrow(new IllegalStateException("audit unavailable"))
        .when(failingAudit)
        .recordStructured(
            org.mockito.ArgumentMatchers.anyString(),
            org.mockito.ArgumentMatchers.anyString(),
            org.mockito.ArgumentMatchers.isNull(),
            org.mockito.ArgumentMatchers.anyMap(),
            org.mockito.ArgumentMatchers.anyString());
    BusinessDataResetService failingService =
        new BusinessDataResetService(
            entityManager,
            tasks,
            projects,
            trafficProxy,
            trafficSessions,
            runtime,
            conversations,
            failingAudit,
            transactionManager);

    assertThatThrownBy(() -> failingService.clear("CLEAR"))
        .isInstanceOf(IllegalStateException.class)
        .hasMessage("audit unavailable");

    assertThat(projects.findById(project.getId())).isPresent();
    verify(conversations, never()).evictAllLocal();
  }

  @Test
  void requiresExactConfirmationPhrase() {
    assertThatThrownBy(() -> service.clear("clear"))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("CLEAR");
    verify(trafficProxy, never()).status();
  }

  private AssessmentProject project() {
    AssessmentProject project = new AssessmentProject();
    project.setName("项目");
    project.setAuthorizationStatement("已授权");
    project.setAuthorizationValidFrom(Instant.now().minusSeconds(60));
    project.setAuthorizationExpiresAt(Instant.now().plusSeconds(3600));
    project.setStatus("ACTIVE");
    project.setOwner("admin");
    return project;
  }

  private AuthorizedTarget target() {
    AuthorizedTarget target = new AuthorizedTarget();
    target.setName("目标");
    target.setTargetValue("127.0.0.1");
    target.setTargetType("IP");
    target.setAuthorizationNote("已授权");
    return target;
  }

  private SecurityTask task(Long projectId, Long targetId, String status) {
    SecurityTask task = new SecurityTask();
    task.setProjectId(projectId);
    task.setTargetId(targetId);
    task.setToolCode("tcp_ports");
    task.setStatus(status);
    task.setProgress(100);
    return task;
  }

  private AuditLog audit(String action) {
    AuditLog log = new AuditLog();
    log.setAction(action);
    log.setResourceType("TEST");
    log.setResult("SUCCESS");
    return log;
  }

  private TrafficProxyService.Status proxyStatus(boolean running) {
    return new TrafficProxyService.Status(
        running, "127.0.0.1", 19080, 0, null, "ASK", false, "", false);
  }
}
