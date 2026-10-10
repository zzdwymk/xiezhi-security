package com.bachelor.toolbox.traffic;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.dependency.DependencyDetectionService;
import com.bachelor.toolbox.dependency.SystemDependenciesResponse;
import com.bachelor.toolbox.project.ProjectAuthorizationService;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.AuthorizedTargetRepository;
import com.bachelor.toolbox.target.PortRangeParser;
import com.bachelor.toolbox.target.TargetPolicyService;
import com.bachelor.toolbox.target.TargetService;
import com.bachelor.toolbox.tool.SqlmapScanTool;
import com.bachelor.toolbox.tool.FindingDraft;
import com.bachelor.toolbox.tool.ToolExecutionObserver;
import com.bachelor.toolbox.tool.ToolExecutionResult;
import com.bachelor.toolbox.tool.XrayScanTool;
import com.bachelor.toolbox.tool.zap.ZapDaemon;
import com.bachelor.toolbox.tool.zap.ZapDaemonSupplier;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** Tests the persistence boundary with a real ledger service and entirely mocked scanners. */
class TrafficScanLifecycleTests {
  private static final long SCAN_ID = 41L;
  private static final String SCAN_URL = "http://127.0.0.1:8080/page?id=1";
  private final TrafficScanLedgerRepository repository = mock(TrafficScanLedgerRepository.class);
  private final TrafficScanLedgerService ledger = new TrafficScanLedgerService(repository);
  private final TrafficPacketRepository packets = mock(TrafficPacketRepository.class);
  private final TargetService targets = mock(TargetService.class);
  private final AuthorizedTargetRepository targetRepository = mock(AuthorizedTargetRepository.class);
  private final ZapDaemonSupplier supplier = mock(ZapDaemonSupplier.class);
  private final ZapDaemon daemon = mock(ZapDaemon.class);
  private final DependencyDetectionService dependencies = mock(DependencyDetectionService.class);
  private final XrayScanTool xray = mock(XrayScanTool.class);
  private final SqlmapScanTool sqlmap = mock(SqlmapScanTool.class);
  private final List<SavedState> saves = new ArrayList<>();
  private TrafficScanService service;

  // Snapshot values when saved: Mockito captors alone would retain the same mutable entity.
  private record SavedState(Long id, String status, int hitCount, String resultJson,
      Instant startedAt, Instant finishedAt) {
    static SavedState of(TrafficScanLedger entry) {
      return new SavedState(entry.getId(), entry.getStatus(), entry.getHitCount(),
          entry.getResultJson(), entry.getStartedAt(), entry.getFinishedAt());
    }
  }

  @BeforeEach
  void setUp() throws Exception {
    when(repository.saveAndFlush(any(TrafficScanLedger.class))).thenAnswer(invocation -> {
      TrafficScanLedger entry = invocation.getArgument(0);
      entry.setId(SCAN_ID);
      saves.add(SavedState.of(entry));
      return entry;
    });
    when(repository.save(any(TrafficScanLedger.class))).thenAnswer(invocation -> {
      TrafficScanLedger entry = invocation.getArgument(0);
      saves.add(SavedState.of(entry));
      return entry;
    });
    TrafficPacket packet = new TrafficPacket();
    packet.setId(1L);
    packet.setTargetId(2L);
    packet.setHost("127.0.0.1");
    packet.setScheme("http");
    packet.setPort(8080);
    packet.setPath("/page?id=1");
    packet.setMethod("GET");
    AuthorizedTarget target = new AuthorizedTarget();
    target.setId(2L);
    target.setTargetValue("127.0.0.1");
    target.setAllowedPorts("8080");
    when(packets.findById(1L)).thenReturn(Optional.of(packet));
    when(targets.get(2L)).thenReturn(target);
    when(dependencies.detect(false)).thenReturn(new SystemDependenciesResponse("win", "x64", "H2",
        List.of(new SystemDependenciesResponse.DependencyStatus("OWASP ZAP", "AVAILABLE",
            "2.17.0", "/zap", false, "PROXY_SCANNER", "ready", null, null))));
    when(supplier.create()).thenAnswer(invocation -> {
      assertThat(saves).as("execution must start only after its RUNNING row is committed")
          .isNotEmpty();
      assertThat(saves.get(0).status()).isEqualTo("RUNNING");
      assertThat(saves.get(0).id()).isEqualTo(SCAN_ID);
      return daemon;
    });
    when(daemon.startActiveScan(any(), anyString(), anyString(), anyBoolean())).thenReturn("7");
    when(daemon.activeScanProgress("7")).thenReturn(100);
    when(daemon.alerts()).thenReturn(List.of(new ZapDaemon.ZapAlert(SCAN_URL,
        "SQL Injection", "HIGH", "High", "89", "Fixture evidence", 1)));
    PortRangeParser ports = new PortRangeParser();
    service = new TrafficScanService(packets, targets, new TargetPolicyService(false, ports),
        targetRepository, supplier, dependencies, xray, sqlmap, mock(AuditService.class),
        ledger, ports, Duration.ofSeconds(2));
  }

  @Test
  void committedRunningRecordBecomesCompletedWithEvidenceWithoutNotifications() throws Exception {
    AtomicInteger announcedRecords = new AtomicInteger();
    var result = service.zapScan(1L, null, new TrafficScanService.ZapScanListener() {
      @Override public void onRecord(Long scanId) {
        assertThat(scanId).isEqualTo(SCAN_ID);
        assertThat(saves.get(0).status()).isEqualTo("RUNNING");
        announcedRecords.incrementAndGet();
      }
    });

    assertThat(result.status()).isEqualTo("COMPLETED");
    assertThat(result.scanId()).isEqualTo(SCAN_ID);
    assertThat(announcedRecords.get()).isEqualTo(1);
    assertThat(saves).extracting(SavedState::id).containsOnly(SCAN_ID);
    assertThat(saves.get(0).startedAt()).isNotNull();
    assertThat(saves.get(0).finishedAt()).isNull();
    SavedState completed = saves.get(saves.size() - 1);
    assertThat(completed.status()).isEqualTo("COMPLETED");
    assertThat(completed.finishedAt()).isNotNull();
    assertThat(completed.hitCount()).isEqualTo(1);
    var stored = new ObjectMapper().readTree(completed.resultJson());
    assertThat(stored.path("scanId").asLong()).isEqualTo(SCAN_ID);
    assertThat(stored.path("hits").get(0).path("title").asText()).isEqualTo("SQL Injection");
    assertThat(stored.path("probes").size()).isEqualTo(1);
    assertThat(saves.stream().anyMatch(saved -> "RUNNING".equals(saved.status())
        && saved.hitCount() == 1 && saved.resultJson().contains("SQL Injection"))).isTrue();
    verify(repository).saveAndFlush(any(TrafficScanLedger.class));
    verify(daemon).close();
  }

  @Test
  void disconnectedBrowserStillCompletesAndPersistsEvidence() throws Exception {
    AtomicInteger deliveryAttempts = new AtomicInteger();
    var result = service.zapScan(1L, null, new TrafficScanService.ZapScanListener() {
      @Override public void onRecord(Long scanId) {
        deliveryAttempts.incrementAndGet();
        throw new IllegalStateException("browser disconnected");
      }
      @Override public void onStart(String url) { deliveryAttempts.incrementAndGet(); }
      @Override public void onHit(TrafficScanService.TargetedScanHit hit) {
        deliveryAttempts.incrementAndGet();
      }
    });

    assertThat(result.status()).isEqualTo("COMPLETED");
    assertThat(deliveryAttempts.get()).isEqualTo(1);
    SavedState completed = saves.get(saves.size() - 1);
    assertThat(completed.status()).isEqualTo("COMPLETED");
    assertThat(new ObjectMapper().readTree(completed.resultJson()).path("hits").size()).isEqualTo(1);
    verify(daemon).startActiveScan(any(), anyString(), anyString(), anyBoolean());
  }

  @Test
  void failedInitialPersistencePreventsEngineExecutionAndSecondInsert() {
    when(repository.saveAndFlush(any(TrafficScanLedger.class)))
        .thenThrow(new IllegalStateException("database unavailable"));

    assertThatThrownBy(() -> service.zapScan(1L, null)).isInstanceOf(ApiException.class)
        .hasMessageContaining("未启动");

    verifyNoInteractions(supplier, daemon, xray, sqlmap);
    verify(repository, never()).save(any(TrafficScanLedger.class));
  }

  @Test
  void engineFailureUpdatesOriginalRecordWithFailureResult() throws Exception {
    when(daemon.startActiveScan(any(), anyString(), anyString(), anyBoolean()))
        .thenThrow(new ApiException("fixture engine failure"));

    var result = service.zapScan(1L, null);

    assertThat(result.status()).isEqualTo("FAILED");
    assertThat(result.scanId()).isEqualTo(SCAN_ID);
    assertThat(saves).extracting(SavedState::id).containsOnly(SCAN_ID);
    SavedState failed = saves.get(saves.size() - 1);
    assertThat(failed.status()).isEqualTo("FAILED");
    assertThat(failed.finishedAt()).isNotNull();
    assertThat(new ObjectMapper().readTree(failed.resultJson()).path("status").asText())
        .isEqualTo("FAILED");
  }

  @Test
  void failedFinalPersistenceCannotReportSuccessfulArchive() {
    when(repository.save(any(TrafficScanLedger.class))).thenAnswer(invocation -> {
      TrafficScanLedger entry = invocation.getArgument(0);
      if ("COMPLETED".equals(entry.getStatus())) throw new IllegalStateException("disk full");
      saves.add(SavedState.of(entry));
      return entry;
    });

    assertThatThrownBy(() -> service.zapScan(1L, null)).isInstanceOf(ApiException.class)
        .hasMessageContaining("结果保存失败");
    assertThat(saves).allMatch(saved -> "RUNNING".equals(saved.status()));
  }

  @Test
  void lateXrayCallbacksCannotOverwriteTerminalStatusOrEvidence() throws Exception {
    AtomicReference<Consumer<FindingDraft>> tailer = new AtomicReference<>();
    AtomicReference<ToolExecutionObserver> observer = new AtomicReference<>();
    when(xray.execute(any(), any(), any(), any())).thenAnswer(invocation -> {
      observer.set(invocation.getArgument(2));
      tailer.set(invocation.getArgument(3));
      return new ToolExecutionResult("fixture complete", Map.of("executionVerified", true), List.of());
    });

    var result = service.xrayScan(1L, null);
    assertThat(result.status()).isEqualTo("COMPLETED");
    int terminalSaveCount = saves.size();
    SavedState completed = saves.get(terminalSaveCount - 1);

    // A tailer that was blocked during shutdown must not revive the completed operation.
    tailer.get().accept(new FindingDraft("Late callback", "HIGH", "description", "evidence", "fix"));
    observer.get().heartbeat("late process heartbeat");

    assertThat(saves).hasSize(terminalSaveCount);
    assertThat(saves.get(saves.size() - 1)).isEqualTo(completed);
    assertThat(completed.status()).isEqualTo("COMPLETED");
    assertThat(completed.hitCount()).isZero();
    assertThat(result.hits()).isEmpty();
  }

  @Test
  void restartMarksInterruptedRecordFailedAndPreservesPartialEvidence() throws Exception {
    TrafficScanLedger interrupted = new TrafficScanLedger();
    interrupted.setId(SCAN_ID);
    interrupted.setStatus("RUNNING");
    interrupted.setHitCount(1);
    interrupted.setResultJson("{\"scanId\":41,\"status\":\"RUNNING\","
        + "\"hits\":[{\"title\":\"SQL Injection\",\"severity\":\"HIGH\"}]}");
    when(repository.findByStatus("RUNNING")).thenReturn(List.of(interrupted));

    ledger.recoverInterruptedScans();

    assertThat(interrupted.getStatus()).isEqualTo("FAILED");
    assertThat(interrupted.getFinishedAt()).isNotNull();
    assertThat(interrupted.getHitCount()).isEqualTo(1);
    var stored = new ObjectMapper().readTree(interrupted.getResultJson());
    assertThat(stored.path("status").asText()).isEqualTo("FAILED");
    assertThat(stored.path("hits").get(0).path("title").asText()).isEqualTo("SQL Injection");
    verify(repository).save(interrupted);
    verifyNoInteractions(supplier, daemon, xray, sqlmap);
  }

  @Test
  void listAndRecentRejectNonAdminBeforeReadingRecords() {
    ProjectAuthorizationService authorization = mock(ProjectAuthorizationService.class);
    doThrow(new ApiException("仅管理员可访问")).when(authorization).requireAdmin();
    ledger.setAuthorization(authorization);

    assertThatThrownBy(() -> ledger.list(0, 20, null)).isInstanceOf(ApiException.class)
        .hasMessageContaining("管理员");
    assertThatThrownBy(ledger::recent).isInstanceOf(ApiException.class)
        .hasMessageContaining("管理员");
    verifyNoInteractions(repository);
  }

  @Test
  void listAndRecentRejectMissingAuthorizationBeforeReadingRecords() {
    assertThatThrownBy(() -> ledger.list(0, 20, null)).isInstanceOf(ApiException.class)
        .hasMessageContaining("访问权限");
    assertThatThrownBy(ledger::recent).isInstanceOf(ApiException.class)
        .hasMessageContaining("访问权限");
    verifyNoInteractions(repository);
  }
}
