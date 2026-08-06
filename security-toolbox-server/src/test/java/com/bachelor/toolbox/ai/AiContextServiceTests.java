package com.bachelor.toolbox.ai;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

import com.bachelor.toolbox.audit.AuditLogRepository;
import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.finding.Finding;
import com.bachelor.toolbox.finding.FindingRepository;
import com.bachelor.toolbox.project.AssessmentProjectService;
import com.bachelor.toolbox.task.SecurityTask;
import com.bachelor.toolbox.task.SecurityTaskRepository;
import com.bachelor.toolbox.traffic.TrafficPacket;
import com.bachelor.toolbox.traffic.TrafficPacketRepository;
import com.bachelor.toolbox.vulnerability.VulnerabilityDefinitionRepository;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class AiContextServiceTests {
  private final AssessmentProjectService projectService = mock(AssessmentProjectService.class);
  private final SecurityTaskRepository tasks = mock(SecurityTaskRepository.class);
  private final FindingRepository findings = mock(FindingRepository.class);
  private final VulnerabilityDefinitionRepository vulnerabilities =
      mock(VulnerabilityDefinitionRepository.class);
  private final AuditLogRepository audits = mock(AuditLogRepository.class);
  private final TrafficPacketRepository traffic = mock(TrafficPacketRepository.class);
  private final AiContextService service =
      new AiContextService(projectService, tasks, findings, vulnerabilities, audits, traffic);
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
}
