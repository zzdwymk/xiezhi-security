package com.bachelor.toolbox.ai;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

import com.bachelor.toolbox.audit.AuditLogRepository;
import com.bachelor.toolbox.audit.AuditLog;
import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.finding.Finding;
import com.bachelor.toolbox.finding.FindingRepository;
import com.bachelor.toolbox.project.AssessmentProjectService;
import com.bachelor.toolbox.task.SecurityTask;
import com.bachelor.toolbox.task.SecurityTaskRepository;
import com.bachelor.toolbox.traffic.TrafficPacket;
import com.bachelor.toolbox.traffic.TrafficPacketRepository;
import com.bachelor.toolbox.traffic.TrafficSession;
import com.bachelor.toolbox.traffic.TrafficSessionRepository;
import com.bachelor.toolbox.vulnerability.VulnerabilityDefinitionRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;

class AiContextServiceTests {
  private final AssessmentProjectService projectService = mock(AssessmentProjectService.class);
  private final SecurityTaskRepository tasks = mock(SecurityTaskRepository.class);
  private final FindingRepository findings = mock(FindingRepository.class);
  private final VulnerabilityDefinitionRepository vulnerabilities =
      mock(VulnerabilityDefinitionRepository.class);
  private final AuditLogRepository audits = mock(AuditLogRepository.class);
  private final TrafficPacketRepository traffic = mock(TrafficPacketRepository.class);
  private final TrafficSessionRepository trafficSessions = mock(TrafficSessionRepository.class);
  private final AiContextService service =
      new AiContextService(
          projectService,
          tasks,
          findings,
          vulnerabilities,
          audits,
          traffic,
          trafficSessions,
          new ObjectMapper());
  @Test
  void reloadsReferencesAndRemovesCredentialsAndRawTraffic() {
    Finding finding = new Finding();
    finding.setId(2L);
    finding.setTargetId(7L);
    finding.setTitle("配置泄露");
    finding.setSeverity("HIGH");
    finding.setDescription("Authorization: Bearer abc.secret and password=hunter2");
    finding.setRemediation("rotate token=xyz");
    when(findings.findById(2L)).thenReturn(Optional.of(finding));
    TrafficPacket packet = new TrafficPacket();
    packet.setId(3L);
    packet.setTargetId(7L);
    packet.setMethod("POST");
    packet.setScheme("https");
    packet.setHost("example.test");
    packet.setPort(443);
    packet.setPath("/login");
    packet.setRiskLevel("HIGH");
    packet.setRequestHeaders("Cookie: session=must-not-leak");
    packet.setRequestBody("password=must-not-leak");
    when(traffic.findById(3L)).thenReturn(Optional.of(packet));

    String result =
        service.resolve(
            null,
            7L,
            new AiPlanRequest.ContextRefs(7L, null, List.of(2L), null, null, List.of(3L)));
    assertThat(result)
        .contains(
            "配置泄露",
            "Authorization=[REDACTED]",
            "token=[REDACTED]",
            "POST https://example.test:443/login")
        .doesNotContain("hunter2", "must-not-leak", "abc.secret");
    verify(findings).findById(2L);
    verify(traffic).findById(3L);
  }

  @Test
  void rejectsEntityOwnedByAnotherTarget() {
    SecurityTask task = new SecurityTask();
    task.setId(9L);
    task.setTargetId(88L);
    when(tasks.findById(9L)).thenReturn(Optional.of(task));

    assertThatThrownBy(
            () ->
                service.resolve(
                    null,
                    7L,
                    new AiPlanRequest.ContextRefs(null, List.of(9L), null, null, null, null)))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("不属于当前授权目标");  }

  @Test
  void acceptsFrontendGenericRefsAndIgnoresUntrustedDisplayMetadata() {
    SecurityTask task = new SecurityTask();
    task.setId(4L);
    task.setTargetId(7L);
    task.setToolCode("tcp_ports");
    task.setStatus("DONE");
    when(tasks.findById(4L)).thenReturn(Optional.of(task));

    String result =
        service.resolve(
            null, 7L, null, List.of(new AiPlanRequest.ContextRef("task", 4L, 999L, "伪造标题")));
    assertThat(result).contains("id=4", "tcp_ports").doesNotContain("伪造标题");
  }

  @Test
  void answersOneAuditReferenceWithBoundedChineseConclusion() {
    AuditLog audit = new AuditLog();
    audit.setId(114L);
    audit.setAction("UPDATE_PROJECT_STATUS");
    audit.setResourceType("TARGET");
    audit.setResourceId("7");
    audit.setResult("SUCCESS");
    audit.setOperator("admin");
    audit.setCreatedAt(Instant.parse("2026-08-11T14:25:32Z"));
    audit.setDetail("authorization=Bearer secret-value");
    when(audits.findById(114L)).thenReturn(Optional.of(audit));

    String answer =
        service
            .answerAuditQuestion(
                null,
                7L,
                null,
                List.of(new AiPlanRequest.ContextRef("audit", 114L, 7L, "伪造标题")),
                "请结合这条审计日志判断是否符合预期",
                "analyze")
            .orElseThrow();

    assertThat(answer)
        .contains("结论", "判断依据", "进一步核查方向", "更新项目状态", "成功")
        .doesNotContain("secret-value", "伪造标题", "agent-step", "指纹探测");
    verify(audits).findById(114L);
    verifyNoInteractions(tasks, findings, traffic);
  }

  @Test
  void projectAuditReferenceMustBelongToCurrentProject() {
    AuditLog audit = new AuditLog();
    audit.setId(115L);
    audit.setAction("CREATE_PROJECT");
    audit.setResourceType("PROJECT");
    audit.setResourceId("99");
    audit.setResult("SUCCESS");
    when(audits.findById(115L)).thenReturn(Optional.of(audit));

    assertThatThrownBy(
            () ->
                service.answerAuditQuestion(
                    5L,
                    7L,
                    null,
                    List.of(new AiPlanRequest.ContextRef("audit", 115L, null, null)),
                    "请分析审计日志",
                    "analyze"))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("不属于当前评估项目");
  }

  @Test
  void explainsUnboundGlobalAuditWithoutLeakingItsDetails() {
    AuditLog audit = new AuditLog();
    audit.setId(116L);
    audit.setAction("SYNC_VULNERABILITY_CATALOG");
    audit.setResourceType("VULNERABILITY");
    audit.setResourceId("global");
    audit.setResult("SUCCESS");
    audit.setDetail("authorization=Bearer must-not-leak");
    when(audits.findById(116L)).thenReturn(Optional.of(audit));

    String answer =
        service
            .answerAuditQuestion(
                5L,
                7L,
                null,
                List.of(new AiPlanRequest.ContextRef("audit", 116L, null, null)),
                "请分析审计日志",
                "analyze")
            .orElseThrow();

    assertThat(answer)
        .contains("无法确认它属于当前项目和授权目标", "不会读取或展示该记录的具体内容", "进一步核查方向")
        .doesNotContain("must-not-leak", "Bearer", "VULNERABILITY");
  }

  @ParameterizedTest
  @NullSource
  @ValueSource(longs = {0L, -1L})
  void answersAuditForGeneralTrafficSessionWithoutUsingCurrentTarget(Long sessionTargetId) {
    AuditLog audit = new AuditLog();
    audit.setId(112L);
    audit.setAction("STOP_TRAFFIC_PROXY");
    audit.setResourceType("TRAFFIC_SESSION");
    audit.setResourceId("41");
    audit.setResult("SUCCESS");
    audit.setCreatedAt(Instant.parse("2026-08-11T14:20:00Z"));
    audit.setDetail("current target fingerprint must-not-appear");
    TrafficSession session = new TrafficSession();
    session.setId(41L);
    session.setTargetId(sessionTargetId);
    when(audits.findById(112L)).thenReturn(Optional.of(audit));
    when(trafficSessions.findById(41L)).thenReturn(Optional.of(session));

    String answer =
        service
            .answerAuditQuestion(
                null,
                7L,
                null,
                List.of(new AiPlanRequest.ContextRef("audit", 112L, 7L, "审计记录 #112")),
                "请判断这条审计日志是否符合预期",
                "analyze")
            .orElseThrow();

    assertThat(answer)
        .contains("结论", "停止流量代理", "成功", "通用流量会话未绑定授权目标")
        .contains("不能据此判断当前目标的流量或安全状态")
        .doesNotContain("must-not-appear", "指纹探测", "技术栈");
    verify(audits).findById(112L);
    verify(trafficSessions).findById(41L);
    verifyNoInteractions(tasks, findings, traffic);
  }

  @Test
  void rejectsTrafficSessionBoundToAnotherTarget() {
    AuditLog audit = new AuditLog();
    audit.setId(117L);
    audit.setAction("STOP_TRAFFIC_PROXY");
    audit.setResourceType("TRAFFIC_SESSION");
    audit.setResourceId("42");
    audit.setResult("SUCCESS");
    TrafficSession session = new TrafficSession();
    session.setId(42L);
    session.setTargetId(88L);
    when(audits.findById(117L)).thenReturn(Optional.of(audit));
    when(trafficSessions.findById(42L)).thenReturn(Optional.of(session));

    assertThatThrownBy(
            () ->
                service.answerAuditQuestion(
                    null,
                    7L,
                    null,
                    List.of(new AiPlanRequest.ContextRef("audit", 117L, 7L, "审计记录 #117")),
                    "请分析审计日志",
                    "analyze"))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("不属于当前授权目标");
  }
}
