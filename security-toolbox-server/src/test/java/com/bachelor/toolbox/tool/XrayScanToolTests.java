package com.bachelor.toolbox.tool;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.verify;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.target.TargetPolicyService;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.ByteArrayInputStream;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

class XrayScanToolTests {
  // Captured from bundled Xray 1.9.11 scanning an HTTP fixture on 127.0.0.1.
  // The fixture returned HTTP 200 and a custom PoC required HTTP 599 (no match).
  private static final String COMPLETED_LOG = """
      [INFO] [phantasm:phantasm.go:185] 1 pocs have been loaded (debug level will show more details)
      [INFO] [default:dispatcher.go:444] processing GET http://127.0.0.1:8443/
      [INFO] [controller:dispatcher.go:573] controller released, task done
      [*] All pending requests have been scanned
      [*] scanned: 1, pending: 0, requestSent: 2, latency: 0.00ms, failedRatio: 0.00%
      """;
  @TempDir Path work;
  private final XrayScanTool tool =
      new XrayScanTool(
          mock(TargetPolicyService.class),
          new ObjectMapper(),
          mock(ScannerPocSelectionService.class),
          "xray",
          60);

  @Test
  void buildsCommandWithSingleOrMultiplePocs() {
    Path output = Path.of("result.json");
    List<String> command =
        tool.buildCommand(
            URI.create("https://127.0.0.1:8443"),
            List.of(poc("poc-a", "XP-1234567890ABCDEF12345678"), poc("poc-b", "XP-FEDCBA0987654321FEDCBA09")),
            output);

    assertThat(command).containsSubsequence("--plugins", "phantasm");
    assertThat(command).containsSubsequence("--log-level", "info");
    assertThat(command).containsSubsequence("--poc", "poc-a,poc-b");
    assertThat(command).containsSubsequence("--json-output", output.toString());
  }

  @Test
  void allPocsUsesScannerAllModeWithoutExpandingIdsIntoTheCommand() {
    Path output = Path.of("result.json");
    List<String> command =
        tool.buildCommand(
            URI.create("https://127.0.0.1:8443"),
            List.of(poc("poc-a"), poc("poc-b")),
            output,
            true);

    assertThat(command).containsSubsequence("--plugins", "phantasm");
    assertThat(command).doesNotContain("--poc", "poc-a,poc-b");
    assertThat(command).containsSubsequence("--json-output", output.toString());
  }

  @Test
  void parsesJsonResultIntoFindings() {
    String json =
        """
[
  {
    "plugin": "phantasm",
    "poc": "xray-test-poc",
    "target": {"url": "https://127.0.0.1:8443/login"},
    "detail": {"vuln_class": "Xray issue", "level": "high"}
  }
]
""";

    ToolExecutionResult result =
        tool.parseOutput(URI.create("https://127.0.0.1:8443"), List.of(poc("xray-test-poc")), json);

    assertThat(result.findings()).hasSize(1);
    assertThat(result.findings().get(0).severity()).isEqualTo("HIGH");
    assertThat(result.findings().get(0).vulnerabilityCode())
        .isEqualTo("XP-1234567890ABCDEF12345678");
    assertThat(result.data()).containsEntry("selectedPocCount", 1).containsEntry("matchCount", 1);
  }

  @Test
  void rejectsOutOfScopeMatch() {
    String json =
        """
[
  {
    "plugin": "phantasm",
    "poc": "xray-test-poc",
    "target": "https://192.0.2.10:8443/login",
    "detail": {"vuln_class": "Xray issue", "level": "high"}
  }
]
""";

    assertThatThrownBy(
            () ->
                tool.parseOutput(
                    URI.create("https://127.0.0.1:8443"), List.of(poc("xray-test-poc")), json))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("授权范围外");
  }

  @Test
  void acceptsMissingResultFileOnlyWithVerifiedSuccessfulExecution() throws Exception {
    Path output = work.resolve("missing.json");
    assertThat(output).doesNotExist();

    ToolExecutionResult result = tool.parseCompletedOutput(
        URI.create("https://127.0.0.1:8443"), List.of(poc("test-poc")), output,
        COMPLETED_LOG, false);

    assertThat(result.findings()).isEmpty();
    assertThat(result.data()).containsEntry("matchCount", 0)
        .containsEntry("executionVerified", true).containsEntry("requestCount", 2L);
  }

  @Test
  void rejectsOfflineTargetEvenThoughXrayExitsSuccessfullyWithoutJson() {
    // The real Xray process returned exit code 0 and no JSON for a closed loopback port.
    String log = """
        [INFO] [phantasm:phantasm.go:185] 1 pocs have been loaded (debug level will show more details)
        [ERRO] [collector:request.go:25] Get "http://127.0.0.1:8443/": dial tcp 127.0.0.1:8443: connectex: No connection could be made because the target machine actively refused it.
        [INFO] [controller:dispatcher.go:573] controller released, task done
        """;

    assertThatThrownBy(() -> completedResult(log))
        .isInstanceOf(ApiException.class).hasMessageContaining("无法连接目标")
        .hasMessageContaining("目标已开机").hasMessageContaining("检测未完成");
  }

  @Test
  void rejectsMissingPocEvenThoughTargetRepliedAndProcessExitedSuccessfully() {
    String log = """
        [INFO] [phantasm:phantasm.go:185] 0 pocs have been loaded (debug level will show more details)
        [WARN] [controller:dispatcher.go:366] no plugin enabled, nothing will be scanned
        [INFO] [default:dispatcher.go:444] processing GET http://127.0.0.1:8443/
        [INFO] [controller:dispatcher.go:573] controller released, task done
        """;

    assertThatThrownBy(() -> completedResult(log))
        .isInstanceOf(ApiException.class).hasMessageContaining("规则未能加载")
        .hasMessageContaining("没有执行检测");
  }

  @Test
  void requiresAllExplicitlySelectedPocsToLoad() {
    assertThatThrownBy(() -> tool.parseCompletedOutput(
        URI.create("https://127.0.0.1:8443"), List.of(poc("a"), poc("b")),
        work.resolve("result.json"), COMPLETED_LOG, false))
        .isInstanceOf(ApiException.class).hasMessageContaining("部分漏洞检测规则未能加载");
  }

  @Test
  void allPocsModeUsesLoadedRulesInsteadOfCatalogSize() throws Exception {
    ToolExecutionResult result = tool.parseCompletedOutput(
        URI.create("https://127.0.0.1:8443"), List.of(poc("a"), poc("b")),
        work.resolve("result.json"), COMPLETED_LOG, true);

    assertThat(result.data()).containsEntry("executionVerified", true);
  }

  @ParameterizedTest
  @ValueSource(strings = {
      "", "[INFO] controller released, task done",
      "[*] All pending requests have been scanned"
  })
  void rejectsUnverifiedCompletion(String log) {
    assertThatThrownBy(() -> completedResult(log))
        .isInstanceOf(ApiException.class).hasMessageContaining("无法确认本次检测已完成");
  }

  @ParameterizedTest
  @ValueSource(strings = {
      "scanned: 0, pending: 0, requestSent: 2",
      "scanned: 1, pending: 1, requestSent: 2",
      "scanned: 1, pending: 0, requestSent: 0"
  })
  void rejectsNoWorkOrPendingRequests(String statistics) {
    String log = COMPLETED_LOG.replace("scanned: 1, pending: 0, requestSent: 2", statistics);
    assertThatThrownBy(() -> completedResult(log))
        .isInstanceOf(ApiException.class).hasMessageContaining("无法确认本次检测已完成");
  }

  @Test
  void rejectsPartialRequestFailuresDespiteCompletionBanner() {
    assertThatThrownBy(() -> completedResult(COMPLETED_LOG.replace("failedRatio: 0.00%", "failedRatio: 50.00%")))
        .isInstanceOf(ApiException.class).hasMessageContaining("部分检测请求失败");
  }

  @ParameterizedTest
  @ValueSource(strings = {"[WARN] reverse service not configured", "[ERRO] failed to execute poc"})
  void doesNotDiscardRuntimeDiagnostics(String diagnostic) {
    assertThatThrownBy(() -> completedResult(COMPLETED_LOG + diagnostic))
        .isInstanceOf(ApiException.class).hasMessageContaining("未能完成全部检查");
  }

  @Test
  void verifiesTheFinalCountersNotEarlierProgress() {
    assertThatThrownBy(() -> completedResult(COMPLETED_LOG
        + "[*] scanned: 2, pending: 1, requestSent: 3, latency: 0.00ms, failedRatio: 0.00%"))
        .isInstanceOf(ApiException.class).hasMessageContaining("无法确认本次检测已完成");
  }

  @Test
  void ignoresAnsiColorSequencesInExecutionRecords() throws Exception {
    assertThat(completedResult(COMPLETED_LOG.replace("[INFO]", "\u001b[32m[INFO]\u001b[0m"))
        .data()).containsEntry("executionVerified", true);
  }

  @ParameterizedTest
  @NullAndEmptySource
  @ValueSource(strings = {" ", "null", "{}", "true", "42", "[null]", "[{}]", "[1]",
      "{\"error\":\"failed\"}", "{\"results\":[],\"error\":\"failed\"}",
      "{\"results\":[],\"success\":false}", "{\"results\":null}", "{\"items\":{}}",
      "[] {}", "[] trailing", "[", "{\"results\":[],\"results\":[]}"})
  void rejectsMalformedOrUnknownResultsInsteadOfReportingNoFindings(String json) {
    assertThatThrownBy(() -> tool.parseOutput(
        URI.create("https://127.0.0.1:8443"), List.of(poc("test-poc")), json))
        .isInstanceOf(ApiException.class);
  }

  @Test
  void doesNotTreatAnExistingEmptyResultFileLikeAnAbsentNoMatchFile() throws Exception {
    Files.writeString(work.resolve("result.json"), "");
    assertThatThrownBy(() -> completedResult(COMPLETED_LOG))
        .isInstanceOf(ApiException.class).hasMessageContaining("结果为空");
  }

  @Test
  void acceptsExplicitEmptyResultsAfterVerifiedExecution() throws Exception {
    Files.writeString(work.resolve("result.json"), "[]");
    assertThat(completedResult(COMPLETED_LOG).data()).containsEntry("matchCount", 0);
  }

  @Test
  void stopsAndJoinsResultTailerBeforeReportingCompletion() throws Exception {
    CountDownLatch started = new CountDownLatch(1);
    CountDownLatch stopped = new CountDownLatch(1);
    Thread tailer = new Thread(() -> {
      started.countDown();
      try {
        Thread.sleep(30_000);
      } catch (InterruptedException expected) {
        Thread.currentThread().interrupt();
      } finally {
        stopped.countDown();
      }
    });
    tailer.start();
    assertThat(started.await(1, TimeUnit.SECONDS)).isTrue();

    assertThat(tool.stopTailer(tailer)).isTrue();
    assertThat(tailer.isAlive()).isFalse();
    assertThat(stopped.getCount()).isZero();
  }

  @Test
  void returnsCancellationTypeAndTerminatesProcess() throws Exception {
    Process process = mock(Process.class);
    when(process.getInputStream()).thenReturn(new ByteArrayInputStream(new byte[0]));
    when(process.isAlive()).thenReturn(true);
    ToolExecutionObserver observer = new ToolExecutionObserver() {
      @Override public boolean isCancellationRequested() { return true; }
    };

    assertThatThrownBy(() -> tool.waitFor(process, observer, "test", 60))
        .isInstanceOf(CancellationException.class);
    verify(process).destroyForcibly();
  }

  @Test
  void returnsTimeoutTypeInsteadOfGenericFailure() throws Exception {
    Process process = mock(Process.class);
    when(process.getInputStream()).thenReturn(new ByteArrayInputStream(new byte[0]));
    when(process.waitFor(250, TimeUnit.MILLISECONDS)).thenReturn(false);

    assertThatThrownBy(() -> tool.waitFor(process, ToolExecutionObserver.NOOP, "test", 0))
        .isInstanceOf(TimeoutException.class);
    verify(process).destroyForcibly();
  }

  private ToolExecutionResult completedResult(String stdout) throws Exception {
    return tool.parseCompletedOutput(URI.create("https://127.0.0.1:8443"),
        List.of(poc("test-poc")), work.resolve("result.json"), stdout, false);
  }

  @Test
  void copiesConfigTemplatesSuccessfully() throws Exception {
    Path tempDir = java.nio.file.Files.createTempDirectory("xray-test-config-");
    try {
      tool.copyConfigTemplates(tempDir, "xray");
      assertThat(tempDir.resolve("config.yaml")).exists();
      assertThat(tempDir.resolve("module.xray.yaml")).exists();
      assertThat(tempDir.resolve("plugin.xray.yaml")).exists();
      assertThat(tempDir.resolve("xray.yaml")).exists();
    } finally {
      org.springframework.util.FileSystemUtils.deleteRecursively(tempDir);
    }
  }

  private ScannerPocSelectionService.SelectedPoc poc(String externalId) {
    return poc(externalId, "XP-1234567890ABCDEF12345678");
  }

  private ScannerPocSelectionService.SelectedPoc poc(String externalId, String code) {
    return new ScannerPocSelectionService.SelectedPoc(
        code,
        externalId,
        "Xray issue",
        "HIGH",
        Path.of("poc.yaml"),
        "0".repeat(64));
  }
}
