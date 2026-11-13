package com.bachelor.toolbox.traffic;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.project.ProjectTarget;
import com.bachelor.toolbox.project.ProjectTargetRepository;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** 抓包按 id 读取的目标归属校验（防 IDOR）——Round 35。 */
@DisplayName("抓包 GET by id 归属校验（Round 35）")
class TrafficProxyPacketAccessTests {
  private final TrafficSessionRepository sessions = mock(TrafficSessionRepository.class);
  private final TrafficPacketRepository packets = mock(TrafficPacketRepository.class);
  private final TrafficSuggestionRepository suggestions = mock(TrafficSuggestionRepository.class);
  private final ProjectTargetRepository projectTargets = mock(ProjectTargetRepository.class);
  private final com.bachelor.toolbox.project.ProjectAuthorizationService authorization =
      mock(com.bachelor.toolbox.project.ProjectAuthorizationService.class);

  private TrafficProxyService service() {
    return new TrafficProxyService(
        sessions, packets, suggestions, mock(TrafficAnalysisService.class),
        mock(com.bachelor.toolbox.target.TargetService.class),
        mock(com.bachelor.toolbox.target.TargetPolicyService.class),
        mock(TrafficCaptureFilterService.class),
        mock(com.bachelor.toolbox.audit.AuditService.class),
        mock(MitmCertificateAuthority.class), mock(TrafficAssetSyncService.class),
        mock(org.springframework.transaction.PlatformTransactionManager.class),
        projectTargets, authorization);
  }

  private TrafficPacket packet(long id, long targetId) {
    TrafficPacket p = new TrafficPacket();
    p.setId(id);
    p.setTargetId(targetId);
    return p;
  }

  @Test
  @DisplayName("PA-1 绑定向他人项目的外部目标 → 拒绝读取")
  void rejectsPacketOfInaccessibleTarget() {
    when(packets.findById(9L)).thenReturn(Optional.of(packet(9L, 77L)));
    var link = new ProjectTarget();
    link.setProjectId(3L);
    link.setTargetId(77L);
    when(projectTargets.findByTargetId(77L)).thenReturn(List.of(link));
    when(authorization.requireAccess(3L)).thenThrow(new ApiException("无权访问"));
    assertThatThrownBy(() -> service().getPacket(9L))
        .isInstanceOf(ApiException.class).hasMessageContaining("无权访问该流量记录");
  }

  @Test
  @DisplayName("PA-2 目标属可访问项目 → 正常返回")
  void allowsAccessiblePacket() {
    TrafficPacket p = packet(9L, 77L);
    when(packets.findById(9L)).thenReturn(Optional.of(p));
    var link = new ProjectTarget();
    link.setProjectId(3L);
    link.setTargetId(77L);
    when(projectTargets.findByTargetId(77L)).thenReturn(List.of(link));
    when(authorization.requireAccess(3L))
        .thenReturn(new com.bachelor.toolbox.project.AssessmentProject());
    org.assertj.core.api.Assertions.assertThat(service().getPacket(9L)).isSameAs(p);
  }

  @Test
  @DisplayName("PA-3 未绑定目标(targetId=0，开放代理) → 允许（保持原行为）")
  void allowsUnboundPacket() {
    TrafficPacket p = packet(9L, 0L);
    when(packets.findById(9L)).thenReturn(Optional.of(p));
    org.assertj.core.api.Assertions.assertThat(service().getPacket(9L)).isSameAs(p);
  }
}
