package com.bachelor.toolbox.traffic;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.asyncDispatch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.request;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.bachelor.toolbox.auth.User;
import com.bachelor.toolbox.audit.AuditLog;
import com.bachelor.toolbox.audit.AuditLogRepository;
import com.bachelor.toolbox.audit.AuditRequestContextFilter;
import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.project.AssessmentProject;
import com.bachelor.toolbox.project.AssessmentProjectRepository;
import com.bachelor.toolbox.project.ProjectAuthorizationService;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.stubbing.Answer;
import org.mockito.ArgumentCaptor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

class TrafficScanStreamSecurityTests {
  private final ExecutorService worker = Executors.newSingleThreadExecutor();
  private final TrafficScanService scans = mock(TrafficScanService.class);
  private final AssessmentProjectRepository projects = mock(AssessmentProjectRepository.class);
  private final ProjectAuthorizationService authorization = new ProjectAuthorizationService(projects);
  private final AuditLogRepository auditLogs = mock(AuditLogRepository.class);
  private final AuditService audit = new AuditService(auditLogs);
  private final AtomicReference<Thread> scanThread = new AtomicReference<>();
  private MockMvc mvc;

  @BeforeEach
  void setUp() {
    SecurityContextHolder.clearContext();
    mvc = MockMvcBuilders.standaloneSetup(new TrafficProxyController(
        null, null, null, null, null, null, scans, null, null, worker))
        .addFilters(new AuditRequestContextFilter()).build();
    when(projects.findById(1L)).thenReturn(Optional.of(project(1L, "alice")));
    when(projects.findById(2L)).thenReturn(Optional.of(project(2L, "bob")));
    // Real project authorization runs on the worker; scanner processes are never started.
    Answer<TrafficScanService.TargetedScanResult> scan = invocation -> {
      scanThread.set(Thread.currentThread());
      Long id = invocation.getArgument(0);
      audit.record("SCAN", "TRAFFIC_PACKET", id, "test", "STARTED");
      authorization.requireAccess(id);
      var result = new TrafficScanService.TargetedScanResult(
          id, invocation.getMethod().getName(), "COMPLETED", List.of(), List.of(),
          authorization.currentUsername());
      TrafficScanService.ZapScanListener listener = invocation.getArgument(2);
      listener.onComplete(result);
      return result;
    };
    when(scans.zapScan(anyLong(), any(), any())).thenAnswer(scan);
    when(scans.xrayScan(anyLong(), any(), any())).thenAnswer(scan);
    when(scans.sqlmapScan(anyLong(), any(), any())).thenAnswer(scan);
  }

  @AfterEach
  void tearDown() throws InterruptedException {
    SecurityContextHolder.clearContext();
    worker.shutdownNow();
    assertThat(worker.awaitTermination(5, TimeUnit.SECONDS)).isTrue();
  }

  @ParameterizedTest
  @ValueSource(strings = {"zap", "xray", "sqlmap"})
  void streamUsesRequestUserAndClearsWorkerAfterSuccess(String engine) throws Exception {
    MvcResult pending = start(engine, 1L, "alice");

    String events = events(pending);

    assertThat(events).contains("\"type\":\"complete\"", "\"message\":\"alice\"")
        .doesNotContain("\"type\":\"error\"");
    assertThat(scanThread.get()).isNotSameAs(Thread.currentThread());
    assertWorkerAnonymous();
  }

  @Test
  void zapStreamBudgetFollowsScannerBudgetInsteadOfFourMinuteCutoff() throws Exception {
    when(scans.zapScanStreamTimeoutMillis()).thenReturn(2_100_000L);
    var pending = start("zap", 1L, "alice");
    assertThat(pending.getRequest().getAsyncContext().getTimeout()).isEqualTo(2_100_000L);
    assertThat(events(pending)).contains("\"type\":\"complete\"");
  }

  @ParameterizedTest
  @ValueSource(strings = {"zap", "xray", "sqlmap"})
  void deniedProjectAccessRemainsAnErrorAndClearsWorker(String engine) throws Exception {
    String events = events(start(engine, 1L, "bob"));

    assertThat(events).contains("\"type\":\"error\"", "无权访问该评估项目")
        .doesNotContain("请先登录", "\"type\":\"complete\"");
    assertWorkerAnonymous();
  }

  @ParameterizedTest
  @ValueSource(strings = {"zap", "xray", "sqlmap"})
  void missingAuthenticationIsNotElevated(String engine) throws Exception {
    String events = events(start(engine, 1L, null));

    assertThat(events).contains("\"type\":\"error\"", "请先登录后再继续操作")
        .doesNotContain("\"type\":\"complete\"");
    assertWorkerAnonymous();
  }

  @ParameterizedTest
  @ValueSource(strings = {"zap", "xray", "sqlmap"})
  void queuedRequestsKeepSeparateUsersAfterRequestContextIsCleared(String engine) throws Exception {
    CountDownLatch release = new CountDownLatch(1);
    worker.submit(() -> {
      if (!release.await(5, TimeUnit.SECONDS)) throw new IllegalStateException("Worker not released");
      return null;
    });
    MvcResult alice;
    MvcResult bob;
    try {
      alice = start(engine, 1L, "alice");
      bob = start(engine, 2L, "bob");
    } finally {
      release.countDown();
    }

    assertThat(events(alice)).contains("\"type\":\"complete\"", "\"message\":\"alice\"");
    assertThat(events(bob)).contains("\"type\":\"complete\"", "\"message\":\"bob\"");
    var captured = ArgumentCaptor.forClass(AuditLog.class);
    verify(auditLogs, times(2)).save(captured.capture());
    assertThat(captured.getAllValues()).extracting(AuditLog::getRequestId).containsExactly(
        alice.getResponse().getHeader(AuditRequestContextFilter.REQUEST_ID_HEADER),
        bob.getResponse().getHeader(AuditRequestContextFilter.REQUEST_ID_HEADER));
    assertThat(captured.getAllValues()).extracting(AuditLog::getSourceIp)
        .containsExactly("192.0.2.1", "192.0.2.2");
    assertWorkerAnonymous();
  }

  @Test
  void workerPreviousContextIsRestoredAfterRequestFailure() throws Exception {
    worker.submit(() -> SecurityContextHolder.setContext(context("background")))
        .get(5, TimeUnit.SECONDS);

    assertThat(events(start("sqlmap", 1L, "bob"))).contains("无权访问该评估项目");

    Authentication restored = worker.submit(() -> SecurityContextHolder.getContext().getAuthentication())
        .get(5, TimeUnit.SECONDS);
    assertThat(restored.getName()).isEqualTo("background");
    worker.submit(SecurityContextHolder::clearContext).get(5, TimeUnit.SECONDS);
  }

  private MvcResult start(String engine, Long projectId, String username) throws Exception {
    SecurityContextHolder.setContext(context(username));
    try {
      return mvc.perform(post("/api/traffic/packets/" + projectId + "/" + engine + "-scan/stream")
          .with(request -> {
            request.setRemoteAddr("192.0.2." + projectId);
            return request;
          }))
          .andExpect(request().asyncStarted()).andReturn();
    } finally {
      // Simulate the end of the original HTTP request before a queued scan has started.
      SecurityContextHolder.clearContext();
    }
  }

  private String events(MvcResult pending) throws Exception {
    pending.getAsyncResult(5_000);
    return mvc.perform(asyncDispatch(pending)).andExpect(status().isOk())
        .andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
  }

  private void assertWorkerAnonymous() throws Exception {
    Authentication remaining = worker.submit(() -> SecurityContextHolder.getContext().getAuthentication())
        .get(5, TimeUnit.SECONDS);
    assertThat(remaining).isNull();
  }

  private static SecurityContext context(String username) {
    SecurityContext context = SecurityContextHolder.createEmptyContext();
    if (username != null) {
      User user = new User();
      user.setUsername(username);
      user.setRole("USER");
      context.setAuthentication(new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities()));
    }
    return context;
  }

  private static AssessmentProject project(Long id, String owner) {
    AssessmentProject project = new AssessmentProject();
    project.setId(id);
    project.setOwner(owner);
    return project;
  }
}
