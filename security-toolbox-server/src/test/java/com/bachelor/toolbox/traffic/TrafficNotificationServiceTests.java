package com.bachelor.toolbox.traffic;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.assertj.core.api.Assertions.*;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.notification.NotificationService;
import com.bachelor.toolbox.project.ProjectAuthorizationService;
import com.bachelor.toolbox.project.ProjectTarget;
import com.bachelor.toolbox.project.ProjectTargetRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class TrafficNotificationServiceTests {
  @Test void singleProjectKeepsAdminAudienceAndExactResultLink() {
    NotificationService publisher = mock(NotificationService.class);
    ProjectTargetRepository links = mock(ProjectTargetRepository.class);
    ProjectTarget link = new ProjectTarget(); link.setProjectId(6L);
    when(links.findByTargetId(7L)).thenReturn(List.of(link));
    new TrafficNotificationService(publisher, links, new ObjectMapper()).publish("run-1", 2L, 7L, 8L,
        "XRAY", "COMPLETED", "返回 1 项告警", List.of("HIGH"));
    verify(publisher).publish("traffic:run-1", 6L, true, "traffic", "success", "XRAY 流量测试已完成",
        "返回 1 项告警", "/traffic?packetId=2&scanId=8", List.of("HIGH"));
  }

  @Test void sharedTargetIsNotAssignedToAnArbitraryProject() {
    NotificationService publisher = mock(NotificationService.class);
    ProjectTargetRepository links = mock(ProjectTargetRepository.class);
    ProjectTarget first = new ProjectTarget(); first.setProjectId(6L);
    ProjectTarget second = new ProjectTarget(); second.setProjectId(9L);
    when(links.findByTargetId(7L)).thenReturn(List.of(first, second));
    new TrafficNotificationService(publisher, links, new ObjectMapper()).publish("run-2", 2L, 7L, null,
        "ZAP", "TIMEOUT", "检测未完成", List.of());
    verify(publisher).publish(eq("traffic:run-2"), isNull(), eq(true), eq("traffic"), eq("error"),
        anyString(), eq("检测未完成"), eq("/traffic?packetId=2"), eq(List.of()));
  }

  @Test void resultDetailRequiresAdminBeforeReadingStoredTraffic() {
    TrafficScanLedgerRepository repository = mock(TrafficScanLedgerRepository.class);
    ProjectAuthorizationService authorization = mock(ProjectAuthorizationService.class);
    doThrow(new ApiException("forbidden")).when(authorization).requireAdmin();
    TrafficScanLedgerService service = new TrafficScanLedgerService(repository);
    service.setAuthorization(authorization);
    assertThatThrownBy(() -> service.detail(3L)).isInstanceOf(ApiException.class);
    verifyNoInteractions(repository);
  }

  @Test void resultDetailRestoresAuthoritativePayload() {
    TrafficScanLedgerRepository repository = mock(TrafficScanLedgerRepository.class);
    TrafficScanLedger entry = new TrafficScanLedger(); entry.setId(3L);
    entry.setResultJson("{\"status\":\"TIMEOUT\",\"hits\":[]}");
    when(repository.findById(3L)).thenReturn(Optional.of(entry));
    TrafficScanLedgerService service = new TrafficScanLedgerService(repository);
    service.setAuthorization(mock(ProjectAuthorizationService.class));
    assertThat(service.detail(3L).result().path("status").asText()).isEqualTo("TIMEOUT");
  }
}
