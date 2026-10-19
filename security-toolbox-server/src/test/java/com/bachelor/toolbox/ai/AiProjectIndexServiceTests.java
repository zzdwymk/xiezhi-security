package com.bachelor.toolbox.ai;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.finding.FindingRepository;
import com.bachelor.toolbox.probe.ProbeResultRepository;
import com.bachelor.toolbox.project.AssessmentProject;
import com.bachelor.toolbox.project.AssessmentProjectService;
import com.bachelor.toolbox.project.ProjectTargetRepository;
import com.bachelor.toolbox.recon.ReconResultRepository;
import com.bachelor.toolbox.target.AuthorizedTargetRepository;
import com.bachelor.toolbox.task.SecurityTaskRepository;
import com.bachelor.toolbox.task.SecurityTask;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class AiProjectIndexServiceTests {
  private final AiAgentRuntimeClient runtime = mock(AiAgentRuntimeClient.class);
  private final AssessmentProjectService projects = mock(AssessmentProjectService.class);
  private final ProjectTargetRepository projectTargets = mock(ProjectTargetRepository.class);
  private final AuthorizedTargetRepository targets = mock(AuthorizedTargetRepository.class);
  private final SecurityTaskRepository tasks = mock(SecurityTaskRepository.class);
  private final FindingRepository findings = mock(FindingRepository.class);
  private final ReconResultRepository recon = mock(ReconResultRepository.class);
  private final ProbeResultRepository probes = mock(ProbeResultRepository.class);
  private final com.bachelor.toolbox.asset.DiscoveredPathService discoveredPaths =
      mock(com.bachelor.toolbox.asset.DiscoveredPathService.class);
  private AiProjectIndexService service;

  @BeforeEach
  void setUp() {
    service =
        new AiProjectIndexService(
            runtime, projects, projectTargets, targets, tasks, findings, recon, probes,
            discoveredPaths);
    AssessmentProject project = new AssessmentProject();
    project.setId(1L);
    project.setName("Example assessment");
    project.setStatus("ACTIVE");
    project.setOwner("admin");
    project.setAuthorizationStatement("Authorized security assessment");
    project.setAuthorizationValidFrom(Instant.parse("2026-07-22T00:00:00Z"));
    project.setAuthorizationExpiresAt(Instant.parse("2026-07-30T00:00:00Z"));
    when(projects.get(1L)).thenReturn(project);
    when(projectTargets.findByProjectId(1L)).thenReturn(List.of());
    when(tasks.findAllByProjectIdOrderByCreatedAtAsc(1L)).thenReturn(List.of());
    when(recon.findByProjectIdOrderByCollectedAtDesc(1L)).thenReturn(List.of());
    when(probes.findByProjectIdOrderByDetectedAtDesc(1L)).thenReturn(List.of());
    when(discoveredPaths.listByProject(1L)).thenReturn(List.of());
    when(runtime.enabled()).thenReturn(true);
  }

  @Test
  void indexesRecordedTaskEventWithoutStageWeightedPercentage() {
    SecurityTask task = new SecurityTask();
    task.setId(10L); task.setProjectId(1L); task.setTargetId(9L);
    task.setStatus("TIMEOUT"); task.setProgress(57);
    task.setProgressMessage("任务执行超时");
    when(tasks.findAllByProjectIdOrderByCreatedAtAsc(1L)).thenReturn(List.of(task));
    when(findings.findAllByTaskIdInOrderByCreatedAtAsc(List.of(10L))).thenReturn(List.of());
    assertTrue(service.refreshBestEffort(1L));
    verify(runtime).indexProject(eq(1L), argThat(documents -> documents.stream().anyMatch(d ->
        d.source().equals("task") && d.text().contains("最近执行事件：任务执行超时")
            && !d.text().contains("57%"))));
  }

  @Test
  void indexesBoundedProjectAuthorizationDocument() {
    assertTrue(service.refreshBestEffort(1L));
    verify(runtime)
        .indexProject(
            eq(1L),
            argThat(
                documents ->
                    documents.size() == 1
                        && documents.get(0).text().contains("Authorized security assessment")));
  }

  @Test
  void runtimeFailureDoesNotBlockAgentTurn() {
    doThrow(new AiAgentRuntimeClient.RuntimeUnavailableException("offline"))
        .when(runtime)
        .indexProject(eq(1L), argThat(documents -> true));
    assertFalse(service.refreshBestEffort(1L));
  }

  @Test
  void selectedRecordPrecedesSnapshotDocuments() {
    var reference = new AiAgentRuntimeClient.IndexDocument("本轮引用", "任务 #1 的已脱敏证据", "reference", java.util.Map.of("targetId", "9"));
    assertTrue(service.refreshBestEffort(1L, reference));
    verify(runtime).indexProject(eq(1L), argThat(documents ->
        documents.size() == 2 && documents.get(0).equals(reference)));
  }

  @Test
  void projectOverviewIncludesRecordsBeyondSelectedTarget() {
    var first = new com.bachelor.toolbox.task.SecurityTask();
    first.setId(10L); first.setTargetId(9L); first.setStatus("SUCCESS");
    var second = new com.bachelor.toolbox.task.SecurityTask();
    second.setId(11L); second.setTargetId(20L); second.setStatus("FAILED");
    when(tasks.findAllByProjectIdOrderByCreatedAtAsc(1L)).thenReturn(List.of(first, second));
    when(findings.findAllByTaskIdInOrderByCreatedAtAsc(List.of(10L, 11L))).thenReturn(List.of());
    assertTrue(service.refreshBestEffort(1L));
    verify(runtime).indexProject(eq(1L), argThat(documents -> documents.stream().anyMatch(d ->
        d.source().equals("project") && "project-overview".equals(d.metadata().get("kind"))
            && !d.metadata().containsKey("targetId") && d.text().contains("检测任务总数：2")
            && d.text().contains("FAILED=1") && d.text().contains("SUCCESS=1"))));
  }

  @Test
  void taskSnapshotRedactsResultsErrorsAndLogsWithoutLosingEvidence() throws Exception {
    ObjectMapper mapper = new ObjectMapper();
    String nested = mapper.writeValueAsString(Map.of("api_key", "encoded-key-secret", "open", true));
    SecurityTask task = new SecurityTask();
    task.setId(10L);
    task.setProjectId(1L);
    task.setTargetId(9L);
    task.setStatus("SUCCESS");
    task.setResultJson(mapper.writeValueAsString(Map.of(
        "password", "prefix\"escaped-tail-secret", "body", nested, "port", 80)));
    task.setExecutionLog("received: " + mapper.writeValueAsString(Map.of(
        "response", nested, "token", "log-token-secret", "elapsedMs", 12)) + "; scan finished");
    task.setErrorMessage("diagnostic; password=\"first\\\"error-tail-secret\"; HTTP 200");
    when(tasks.findAllByProjectIdOrderByCreatedAtAsc(1L)).thenReturn(List.of(task));
    when(findings.findAllByTaskIdInOrderByCreatedAtAsc(List.of(10L))).thenReturn(List.of());

    var document = service.collect(1L).stream().filter(d -> d.source().equals("task"))
        .findFirst().orElseThrow();

    assertThat(document.text()).contains("port", "80", "open", "true", "elapsedMs", "12",
            "scan finished", "HTTP 200", "执行日志摘要", "[REDACTED]")
        .doesNotContain("encoded-key-secret", "escaped-tail-secret", "log-token-secret", "error-tail-secret");
    assertThat(document.metadata()).containsEntry("targetId", "9").containsEntry("taskId", "10");
  }

  /**
   * DEF-AI-09 回归：项目授权声明里残留了非登记地址时，索引必须显式写出不一致，
   * 并声明"可执行范围以登记目标为准"。
   *
   * <p>实测场景：换靶机后项目声明的 authorizationStatement 仍是旧地址
   * 192.168.222.128，而本轮登记目标已是 192.168.222.129。模型当时据声明断言
   * "授权范围是 .128"，与提问目标冲突，给出的解释自相矛盾。
   */
  @Test
  void flagsAuthorizationStatementAddressNotInRegisteredTargets() {
    AssessmentProject project = new AssessmentProject();
    project.setId(1L);
    project.setName("Example assessment");
    project.setStatus("ACTIVE");
    project.setAuthorizationStatement("允许对 192.168.222.128 进行端口探测与 HTTP 安全检查");
    when(projects.get(1L)).thenReturn(project);
    var target = new com.bachelor.toolbox.target.AuthorizedTarget();
    target.setId(85L);
    target.setName("靶机-192.168.222.129");
    target.setTargetValue("192.168.222.129");
    target.setTargetType("ip");
    target.setAllowedPorts("22,80");
    target.setEnabled(true);
    var link = new com.bachelor.toolbox.project.ProjectTarget();
    link.setProjectId(1L);
    link.setTargetId(85L);
    when(projectTargets.findByProjectId(1L)).thenReturn(List.of(link));
    when(targets.findAllById(List.of(85L))).thenReturn(List.of(target));

    var conflict =
        service.collect(1L).stream()
            .filter(d -> "authorization-conflict".equals(d.metadata().get("kind")))
            .findFirst()
            .orElseThrow(() -> new AssertionError("授权声明与登记目标不一致时必须产出冲突文档"));

    assertThat(conflict.text())
        .contains("192.168.222.128")
        .contains("192.168.222.129")
        .contains("不在授权范围内")
        .contains("以登记目标与允许端口为准");
    assertThat(conflict.metadata()).containsEntry("projectId", "1");
    // 授权文档本身也要声明"声明只是背景资料、以登记目标为准"。
    var authorization =
        service.collect(1L).stream()
            .filter(d -> "authorization".equals(d.metadata().get("kind")))
            .findFirst()
            .orElseThrow();
    assertThat(authorization.text()).contains("可执行范围说明").contains("以登记目标为准");
  }

  /**
   * DEF-AI-09 反向验证：声明与登记目标一致时**不得**产出冲突文档。
   * 若把冲突检测写成无条件告警，本用例会失败。
   */
  @Test
  void doesNotFlagConflictWhenStatementMatchesRegisteredTargets() {
    AssessmentProject project = new AssessmentProject();
    project.setId(1L);
    project.setName("Example assessment");
    project.setStatus("ACTIVE");
    project.setAuthorizationStatement("允许对 192.168.222.129 进行端口探测与 HTTP 安全检查");
    when(projects.get(1L)).thenReturn(project);
    var target = new com.bachelor.toolbox.target.AuthorizedTarget();
    target.setId(85L);
    target.setName("靶机-192.168.222.129");
    target.setTargetValue("192.168.222.129");
    target.setTargetType("ip");
    target.setAllowedPorts("22,80");
    target.setEnabled(true);
    var link = new com.bachelor.toolbox.project.ProjectTarget();
    link.setProjectId(1L);
    link.setTargetId(85L);
    when(projectTargets.findByProjectId(1L)).thenReturn(List.of(link));
    when(targets.findAllById(List.of(85L))).thenReturn(List.of(target));

    assertThat(service.collect(1L))
        .noneMatch(d -> "authorization-conflict".equals(d.metadata().get("kind")));
  }

  /**
   * DEF-AI-09 边界：声明里出现的是 URL 形式地址（http://host:port/path）时，
   * 也要能取出其中的 IP 做比对，不能因带协议前缀而漏报或误报。
   */
  @Test
  void comparesAddressesInsideUrlFormStatements() {
    AssessmentProject project = new AssessmentProject();
    project.setId(1L);
    project.setName("Example assessment");
    project.setStatus("ACTIVE");
    project.setAuthorizationStatement("已授权 http://192.168.222.128:80/admin 的安全检查");
    when(projects.get(1L)).thenReturn(project);
    var target = new com.bachelor.toolbox.target.AuthorizedTarget();
    target.setId(85L);
    target.setName("靶机-192.168.222.129");
    target.setTargetValue("http://192.168.222.129:80");
    target.setTargetType("url");
    target.setAllowedPorts("80");
    target.setEnabled(true);
    var link = new com.bachelor.toolbox.project.ProjectTarget();
    link.setProjectId(1L);
    link.setTargetId(85L);
    when(projectTargets.findByProjectId(1L)).thenReturn(List.of(link));
    when(targets.findAllById(List.of(85L))).thenReturn(List.of(target));

    var conflict =
        service.collect(1L).stream()
            .filter(d -> "authorization-conflict".equals(d.metadata().get("kind")))
            .findFirst()
            .orElseThrow(() -> new AssertionError("URL 形式的声明地址也必须参与比对"));
    assertThat(conflict.text()).contains("192.168.222.128").doesNotContain("192.168.222.129 不属于");
  }

  /**
   * DEF-AI-09 边界：项目没有任何登记目标时不做冲突判定
   * （此时无法确定"应为"的范围，避免把全部地址误报为越界）。
   */
  @Test
  void skipsConflictCheckWhenProjectHasNoRegisteredTargets() {
    AssessmentProject project = new AssessmentProject();
    project.setId(1L);
    project.setName("Example assessment");
    project.setStatus("ACTIVE");
    project.setAuthorizationStatement("允许对 192.168.222.128 进行检查");
    when(projects.get(1L)).thenReturn(project);
    when(projectTargets.findByProjectId(1L)).thenReturn(List.of());

    assertThat(service.collect(1L))
        .noneMatch(d -> "authorization-conflict".equals(d.metadata().get("kind")));
  }
}
