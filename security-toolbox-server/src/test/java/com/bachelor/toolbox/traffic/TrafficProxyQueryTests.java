package com.bachelor.toolbox.traffic;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.target.TargetPolicyService;
import com.bachelor.toolbox.target.TargetService;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.transaction.PlatformTransactionManager;

@ExtendWith(MockitoExtension.class)
class TrafficProxyQueryTests {
  @Mock private TrafficSessionRepository sessions;
  @Mock private TrafficPacketRepository packets;
  @Mock private TrafficSuggestionRepository suggestions;
  @Mock private TrafficAnalysisService analysis;
  @Mock private TargetService targets;
  @Mock private TargetPolicyService policy;
  @Mock private TrafficCaptureFilterService filters;
  @Mock private AuditService audit;
  @Mock private MitmCertificateAuthority certificateAuthority;
  @Mock private PlatformTransactionManager transactionManager;

  @Test
  void queriesOnlyTheMostRecentTwoHundredStoredPackets() {
    TrafficPacket packet = packet(1L);
    when(packets.findAll(any(Pageable.class))).thenReturn(new PageImpl<>(List.of(packet)));

    assertThat(service().packets()).containsExactly(packet);

    ArgumentCaptor<Pageable> pageable = ArgumentCaptor.forClass(Pageable.class);
    verify(packets).findAll(pageable.capture());
    assertThat(pageable.getValue().getPageNumber()).isZero();
    assertThat(pageable.getValue().getPageSize()).isEqualTo(200);
    assertThat(pageable.getValue().getSort().getOrderFor("createdAt").isDescending()).isTrue();
    assertThat(pageable.getValue().getSort().getOrderFor("id").isDescending()).isTrue();
  }

  @Test
  void appliesTheDatabaseLimitToTheCurrentSessionQuery() {
    TrafficSession session = new TrafficSession();
    session.setId(9L);
    TrafficPacket packet = packet(session.getId());
    when(packets.findAllBySessionIdOrderByCreatedAtDescIdDesc(eq(9L), any(Pageable.class)))
        .thenReturn(List.of(packet));
    TrafficProxyService service = service();
    ReflectionTestUtils.setField(service, "current", session);

    assertThat(service.packets()).containsExactly(packet);

    ArgumentCaptor<Pageable> pageable = ArgumentCaptor.forClass(Pageable.class);
    verify(packets).findAllBySessionIdOrderByCreatedAtDescIdDesc(eq(9L), pageable.capture());
    assertThat(pageable.getValue().getPageNumber()).isZero();
    assertThat(pageable.getValue().getPageSize()).isEqualTo(200);
  }

  private TrafficPacket packet(Long sessionId) {
    TrafficPacket packet = new TrafficPacket();
    packet.setSessionId(sessionId);
    packet.setCreatedAt(Instant.now());
    return packet;
  }

  private TrafficProxyService service() {
    return new TrafficProxyService(
        sessions,
        packets,
        suggestions,
        analysis,
        targets,
        policy,
        filters,
        audit,
        certificateAuthority,
        transactionManager);
  }
}
