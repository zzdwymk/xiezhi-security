package com.bachelor.toolbox.traffic;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.project.ProjectAuthorizationService;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

class TrafficFuzzBatchServiceTests {
  private final TrafficFuzzService fuzz = mock(TrafficFuzzService.class);
  private final TrafficPacketRepository packets = mock(TrafficPacketRepository.class);
  private final TrafficScanLedgerService ledger = mock(TrafficScanLedgerService.class);
  private final TrafficNotificationService notifications = mock(TrafficNotificationService.class);
  private final ProjectAuthorizationService authorization = mock(ProjectAuthorizationService.class);
  private final TrafficFuzzBatchService service = new TrafficFuzzBatchService(fuzz, packets, ledger, notifications, authorization);
  private final TrafficFuzzService.FuzzRequest request =
      new TrafficFuzzService.FuzzRequest(7L, "GET", "http://fixture.test/?q=§name§", "", "", List.of("one"));

  @BeforeEach void setup() {
    for (long id : List.of(1L, 2L)) {
      TrafficPacket packet = new TrafficPacket(); packet.setId(id); packet.setHost("fixture.test");
      when(packets.findById(id)).thenReturn(Optional.of(packet));
      when(fuzz.fuzz(id, request)).thenReturn(response(id, "COMPLETED"));
    }
    when(ledger.record(any())).thenAnswer(call -> { TrafficScanLedger entry = call.getArgument(0); entry.setId(31L); return entry; });
    when(notifications.serialize(any())).thenReturn("{\"results\":{}}");
  }

  private TrafficFuzzService.FuzzResponse response(Long id, String status) {
    return new TrafficFuzzService.FuzzResponse(id, "GET", "http://fixture.test/", List.of(), 1, "LOOP", status,
        "fixture result", 1);
  }

  @Test void twoPacketsAndDuplicateSelectionProduceOneSummaryNotification() {
    var result = service.run(new TrafficFuzzBatchService.Request(List.of(1L, 2L, 1L), request));
    assertThat(result.status()).isEqualTo("COMPLETED");
    assertThat(result.results()).hasSize(2);
    verify(fuzz).fuzz(1L, request); verify(fuzz).fuzz(2L, request);
    verify(notifications).publish(eq(result.batchId()), eq(1L), eq(7L), eq(31L), eq("Fuzz 批量"),
        eq("COMPLETED"), contains("确认完成 2 次请求"), eq(List.of()));
    ArgumentCaptor<TrafficScanLedger> saved = ArgumentCaptor.forClass(TrafficScanLedger.class);
    verify(ledger).record(saved.capture());
    assertThat(saved.getValue().getHitCount()).isZero();
    assertThat(saved.getValue().getResultJson()).isNotBlank();
  }

  @Test void partialTimeoutRetainsEarlierResultsAndNotifiesOnce() {
    when(fuzz.fuzz(2L, request)).thenReturn(response(2L, "TIMEOUT"));
    var result = service.run(new TrafficFuzzBatchService.Request(List.of(1L, 2L), request));
    assertThat(result.results()).hasSize(2);
    assertThat(result.status()).isEqualTo("TIMEOUT");
    verify(notifications).publish(eq(result.batchId()), eq(1L), eq(7L), eq(31L), eq("Fuzz 批量"),
        eq("TIMEOUT"), anyString(), eq(List.of()));
  }

  @Test void unexpectedFailureRetainsPartialResultsAndProducesFailureNotice() {
    when(fuzz.fuzz(2L, request)).thenThrow(new IllegalStateException("private diagnostic"));
    var result = service.run(new TrafficFuzzBatchService.Request(List.of(1L, 2L), request));
    assertThat(result.status()).isEqualTo("FAILED");
    assertThat(result.results()).containsOnlyKeys(1L);
    assertThat(result.message()).doesNotContain("private diagnostic");
    verify(notifications).publish(eq(result.batchId()), eq(1L), eq(7L), eq(31L), eq("Fuzz 批量"),
        eq("FAILED"), anyString(), eq(List.of()));
  }

  @Test void inaccessibleRequestSendsNothingAndPublishesNothing() {
    doThrow(new ApiException("forbidden")).when(authorization).requireAdmin();
    assertThatThrownBy(() -> service.run(new TrafficFuzzBatchService.Request(List.of(1L), request)))
        .isInstanceOf(ApiException.class);
    verifyNoInteractions(packets, fuzz, notifications, ledger);
  }

  @Test void invalidSelectionIsRejectedBeforeAnyExecution() {
    assertThatThrownBy(() -> service.run(new TrafficFuzzBatchService.Request(java.util.Collections.nCopies(201, 1L), request)))
        .isInstanceOf(ApiException.class);
    verifyNoInteractions(packets, fuzz, notifications, ledger);
  }

  @Test void legacySinglePacketEndpointUsesTheSameSingleSummary() {
    TrafficProxyController controller = new TrafficProxyController(null, null, null, null, null,
        fuzz, null, null, null);
    controller.setFuzzBatches(service);
    assertThat(controller.fuzz(1L, request).status()).isEqualTo("COMPLETED");
    verify(fuzz).fuzz(1L, request);
    verify(notifications).publish(anyString(), eq(1L), eq(7L), eq(31L), eq("Fuzz 批量"),
        eq("COMPLETED"), anyString(), eq(List.of()));
  }
}
