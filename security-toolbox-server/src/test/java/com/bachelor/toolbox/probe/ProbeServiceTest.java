package com.bachelor.toolbox.probe;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.fingerprint.FingerprintMatcher;
import com.bachelor.toolbox.fingerprint.FingerprintRuleCatalog;
import com.bachelor.toolbox.project.AssessmentProject;
import com.bachelor.toolbox.project.AssessmentProjectRepository;
import com.bachelor.toolbox.project.ProjectTarget;
import com.bachelor.toolbox.project.ProjectTargetRepository;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.AuthorizedTargetRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class ProbeServiceTest {
  @Mock private ProbeResultRepository results;
  @Mock private AssessmentProjectRepository projects;
  @Mock private ProjectTargetRepository projectTargets;
  @Mock private AuthorizedTargetRepository targets;
  @Mock private FingerprintMatcher fingerprints;

  @Test
  void reportsMissingIdentifiersInChinese() {
    ProbeRequest request = new ProbeRequest();

    assertThatThrownBy(() -> service().probe(request))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("项目 ID 和目标 ID 不能为空");
    verifyNoInteractions(results, projects, projectTargets, targets, fingerprints);
  }

  @Test
  void reportsMissingProjectInChinese() {
    ProbeRequest request = requestFor(7L, null);
    when(projects.findById(1L)).thenReturn(Optional.empty());

    assertThatThrownBy(() -> service().probe(request))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("未找到项目");

    verifyNoInteractions(projectTargets, targets, results, fingerprints);
  }

  @Test
  void reportsMissingTargetInChinese() {
    when(projects.findById(1L)).thenReturn(Optional.of(activeProject()));
    when(projectTargets.findByProjectIdAndTargetId(1L, 7L))
        .thenReturn(Optional.of(new ProjectTarget(1L, 7L)));
    when(targets.findById(7L)).thenReturn(Optional.empty());

    assertThatThrownBy(() -> service().probe(requestFor(7L, null)))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("未找到目标");

    verifyNoInteractions(results, fingerprints);
  }

  @Test
  void rejectsInactiveProjectAuthorizationAsBusinessError() {
    AssessmentProject project = activeProject();
    project.setAuthorizationExpiresAt(Instant.now().minusSeconds(1));
    when(projects.findById(1L)).thenReturn(Optional.of(project));

    assertThatThrownBy(() -> service().probe(requestFor(7L, null)))
        .isInstanceOf(ApiException.class)
        .hasMessage("项目授权已过期或尚未生效");

    verifyNoInteractions(projectTargets, targets, results, fingerprints);
  }

  @Test
  void rejectsProjectAuthorizationThatHasNotStartedAsBusinessError() {
    AssessmentProject project = activeProject();
    project.setAuthorizationValidFrom(Instant.now().plusSeconds(3_600));
    when(projects.findById(1L)).thenReturn(Optional.of(project));

    assertThatThrownBy(() -> service().probe(requestFor(7L, null)))
        .isInstanceOf(ApiException.class)
        .hasMessage("项目授权已过期或尚未生效");

    verifyNoInteractions(projectTargets, targets, results, fingerprints);
  }

  @Test
  void delegatesHistoryToDescendingRepositoryQueries() {
    ProbeResult projectResult = new ProbeResult();
    ProbeResult targetResult = new ProbeResult();
    when(results.findByProjectIdOrderByDetectedAtDescIdDesc(eq(1L), any()))
        .thenReturn(List.of(projectResult));
    when(results.findByProjectIdAndTargetIdOrderByDetectedAtDescIdDesc(
            eq(1L), eq(7L), any()))
        .thenReturn(List.of(targetResult));

    assertThat(service().history(1L)).containsExactly(projectResult);
    assertThat(service().history(1L, 7L)).containsExactly(targetResult);

    verify(results)
        .findByProjectIdOrderByDetectedAtDescIdDesc(
            eq(1L),
            argThat(page -> page.getPageNumber() == 0 && page.getPageSize() == 1_000));
    verify(results)
        .findByProjectIdAndTargetIdOrderByDetectedAtDescIdDesc(
            eq(1L),
            eq(7L),
            argThat(page -> page.getPageNumber() == 0 && page.getPageSize() == 1_000));
  }

  @Test
  void hidesUnexpectedNetworkErrorDetailsFromEvidence() {
    String message =
        org.springframework.test.util.ReflectionTestUtils.invokeMethod(
            service(),
            "friendlyNetworkError",
            new IOException("test-data/private/credential.txt"));

    assertThat(message)
        .isEqualTo("网络请求失败，请检查目标地址和网络状态")
        .doesNotContain("private", "credential");
  }

  @Test
  void persistsUnavailableEvidenceInsteadOfFailingWhenTargetRefusesConnection() throws Exception {
    int closedPort;
    try (ServerSocket socket = new ServerSocket(0)) {
      closedPort = socket.getLocalPort();
    }

    AuthorizedTarget target = authorizedTarget("http://127.0.0.1:" + closedPort, closedPort);
    target.setAllowedPorts(String.valueOf(closedPort));
    stubAuthorizedProject(target);
    when(results.save(any(ProbeResult.class))).thenAnswer(invocation -> invocation.getArgument(0));

    ProbeResult result = service().probe(requestFor(target.getId(), "http://127.0.0.1:" + closedPort));

    assertThat(result.getEvidence()).contains("\"status\":\"UNAVAILABLE\"").contains("连接被拒绝");
    assertThat(result.getWaf()).isEqualTo("未识别");
  }

  @Test
  void usesHttp11ForSuccessfulLocalProbe() throws Exception {
    AtomicReference<String> upgrade = new AtomicReference<>();
    AtomicReference<String> http2Settings = new AtomicReference<>();
    HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext(
        "/",
        exchange -> {
          upgrade.set(exchange.getRequestHeaders().getFirst("Upgrade"));
          http2Settings.set(exchange.getRequestHeaders().getFirst("HTTP2-Settings"));
          byte[] body = "<title>Local probe</title>".getBytes(StandardCharsets.UTF_8);
          exchange.sendResponseHeaders(200, body.length);
          exchange.getResponseBody().write(body);
          exchange.close();
        });
    server.start();

    try {
      int port = server.getAddress().getPort();
      AuthorizedTarget target = authorizedTarget("http://127.0.0.1:" + port, port);
      stubAuthorizedProject(target);
      when(fingerprints.match(any(), any(), any(), any()))
          .thenReturn(
              new FingerprintMatcher.Result(
                  new FingerprintRuleCatalog.CatalogInfo("test", "sha256:test", 0),
                  "Local probe",
                  List.of()));
      when(results.save(any(ProbeResult.class))).thenAnswer(invocation -> invocation.getArgument(0));

      ProbeResult result = service().probe(requestFor(target.getId(), "http://127.0.0.1:" + port));

      assertThat(result.getEvidence()).contains("\"status\":200").contains("Local probe");
      assertThat(upgrade.get()).isNull();
      assertThat(http2Settings.get()).isNull();
    } finally {
      server.stop(0);
    }
  }

  @Test
  void rejectsProbeUrlOutsideAuthorizedHost() {
    AuthorizedTarget target = authorizedTarget("http://127.0.0.1:8080", 8080);
    stubAuthorizedProject(target);

    ProbeRequest request = requestFor(target.getId(), "http://localhost:8080");

    assertThatThrownBy(() -> service().probe(request))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("探测 URL 必须与授权目标使用相同主机");
    verifyNoInteractions(results, fingerprints);
  }

  @Test
  void rejectsProbeUrlOutsideAuthorizedPortRange() {
    AuthorizedTarget target = authorizedTarget("http://127.0.0.1:8080", 8080);
    stubAuthorizedProject(target);

    ProbeRequest request = requestFor(target.getId(), "http://127.0.0.1:9090");

    assertThatThrownBy(() -> service().probe(request))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("探测端口超出授权端口范围");
    verifyNoInteractions(results, fingerprints);
  }

  private void stubAuthorizedProject(AuthorizedTarget target) {
    when(projects.findById(1L)).thenReturn(Optional.of(activeProject()));
    when(projectTargets.findByProjectIdAndTargetId(1L, target.getId()))
        .thenReturn(Optional.of(new ProjectTarget(1L, target.getId())));
    when(targets.findById(target.getId())).thenReturn(Optional.of(target));
  }

  private AssessmentProject activeProject() {
    AssessmentProject project = new AssessmentProject();
    project.setStatus("ACTIVE");
    project.setAuthorizationValidFrom(Instant.now().minusSeconds(3_600));
    project.setAuthorizationExpiresAt(Instant.now().plusSeconds(3_600));
    return project;
  }

  private AuthorizedTarget authorizedTarget(String value, int port) {
    AuthorizedTarget target = new AuthorizedTarget();
    target.setId(7L);
    target.setEnabled(true);
    target.setTargetValue(value);
    target.setAllowedPorts(String.valueOf(port));
    return target;
  }

  private ProbeRequest requestFor(Long targetId, String url) {
    ProbeRequest request = new ProbeRequest();
    request.setProjectId(1L);
    request.setTargetId(targetId);
    request.setUrl(url);
    return request;
  }

  private ProbeService service() {
    return new ProbeService(
        results, projects, projectTargets, targets, fingerprints, new ObjectMapper());
  }
}
