package com.bachelor.toolbox.tool;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.verify;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.target.TargetPolicyService;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.StringReader;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.CancellationException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

class AfrogScanToolTests {
  @TempDir Path work;
  // Captured from bundled Afrog 3.5.7 with a custom PoC against a loopback HTTP fixture.
  // A closed loopback port produces identical started/completed counts and no JSON file.
  private static final String STARTED = "[INF] VULN-SCAN | started   | targets=1 pocs=1 tasks=1\n";
  private static final String COMPLETED = "[INF] VULN-SCAN | completed | tasks=1/1 found=0 duration=0s\n";
  private static final String RESPONSE = """
      [1][afrog-test-poc] Dumped Response
      HTTP/1.0 200 OK
      Server: Local-fixture

      Local fixture body
      """;
  private final AfrogScanTool tool =
      new AfrogScanTool(
          mock(TargetPolicyService.class),
          new ObjectMapper(),
          mock(ScannerPocSelectionService.class),
          "afrog",
          60);

  @Test
  void buildsCommandForSelectedPocDirectory() {
    URI target = URI.create("https://127.0.0.1:8443");
    Path pocs = Path.of("selected-pocs");
    Path output = Path.of("result.json");

    List<String> command = tool.buildCommand(target, pocs, output);

    assertThat(command).containsSubsequence("-t", target.toString(), "-P", pocs.toString());
    assertThat(command).containsSubsequence("-json", output.toString());
    assertThat(command).contains("-disable-update-check", "-curated", "off", "-debug");
    assertThat(command).doesNotContain("-silent");
  }

  @Test
  void parsesJsonArrayIntoFindings() {
    String json =
        """
[
  {
    "id": "afrog-test-poc",
    "fulltarget": "https://127.0.0.1:8443/login",
    "info": {
      "name": "Afrog issue",
      "severity": "high",
      "description": "Matched by Afrog"
    }
  }
]
""";

    ToolExecutionResult result =
        tool.parseOutput(URI.create("https://127.0.0.1:8443"), List.of(poc("afrog-test-poc")), json);

    assertThat(result.findings()).hasSize(1);
    assertThat(result.findings().get(0).severity()).isEqualTo("HIGH");
    assertThat(result.findings().get(0).vulnerabilityCode())
        .isEqualTo("AP-1234567890ABCDEF12345678");
    assertThat(result.data()).containsEntry("selectedPocCount", 1).containsEntry("matchCount", 1);
  }

  @Test
  void rejectsOutOfScopeMatch() {
    String json =
        """
[
  {"id": "afrog-test-poc", "fulltarget": "https://192.0.2.10:8443/", "info": {"name": "Issue"}}
]
""";

    assertThatThrownBy(
            () ->
                tool.parseOutput(
                    URI.create("https://127.0.0.1:8443"), List.of(poc("afrog-test-poc")), json))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("授权范围外");
  }

  @Test
  void acceptsRealNoMatchExecutionWithResponseEvidenceAndNoJsonFile() throws Exception {
    ToolExecutionResult result = completedResult(STARTED + RESPONSE + COMPLETED);

    assertThat(result.data()).containsEntry("matchCount", 0).containsEntry("executionVerified", true)
        .containsEntry("verifiedPocCount", 1L);
  }

  @Test
  void rejectsOfflineExecutionDespiteIdenticalCompletedTaskCounts() {
    assertThatThrownBy(() -> completedResult(STARTED + COMPLETED))
        .isInstanceOf(ApiException.class).hasMessageContaining("未收到目标")
        .hasMessageContaining("目标已开机");
  }

  @Test
  void rejectsResponseMarkersWithoutValidHttpResponses() {
    assertThatThrownBy(() -> completedResult(STARTED + RESPONSE.replace("HTTP/1.0 200 OK", "EOF") + COMPLETED))
        .isInstanceOf(ApiException.class).hasMessageContaining("未收到目标");
  }

  @Test
  void rejectsMissingOrIncompleteExecutionCounters() {
    assertThatThrownBy(() -> completedResult(RESPONSE + COMPLETED))
        .isInstanceOf(ApiException.class).hasMessageContaining("无法确认本次检测已完成");
    assertThatThrownBy(() -> completedResult(STARTED + RESPONSE + COMPLETED.replace("tasks=1/1", "tasks=0/1")))
        .isInstanceOf(ApiException.class).hasMessageContaining("无法确认本次检测已完成");
  }

  @Test
  void rejectsRulesThatDidNotLoad() {
    assertThatThrownBy(() -> completedResult(STARTED.replace("pocs=1", "pocs=0") + COMPLETED))
        .isInstanceOf(ApiException.class).hasMessageContaining("规则未能全部加载");
  }

  @Test
  void requiresResponseEvidenceForEverySelectedPoc() throws Exception {
    String evidence = summarize(STARTED.replace("pocs=1 tasks=1", "pocs=2 tasks=2")
        + RESPONSE + COMPLETED.replace("tasks=1/1", "tasks=2/2"));
    assertThatThrownBy(() -> tool.parseCompletedOutput(URI.create("https://127.0.0.1:8443"),
        List.of(poc("afrog-test-poc"), poc("second-poc")), work.resolve("result.json"), evidence))
        .isInstanceOf(ApiException.class).hasMessageContaining("部分漏洞检测规则未收到");
  }

  @Test
  void ignoresResponseBodyWarningsAndRetainsNoRawRequestOrResponseContent() throws Exception {
    String raw = STARTED + """
        [1][afrog-test-poc] Dumped Request
        GET /fixture HTTP/1.1
        Authorization: secret

        """ + RESPONSE + "[WARN] This is website content, not an engine failure\n"
        + "large body".repeat(300_000) + "\n" + COMPLETED;
    String evidence = summarize(raw);

    assertThat(evidence).doesNotContain("secret", "Server:", "website content", "large body")
        .hasSizeLessThan(500);
    assertThat(completedResult(raw).data()).containsEntry("executionVerified", true);
  }

  @Test
  void handlesActualAnsiColorsAndProgressCarriageReturns() throws Exception {
    String log = (STARTED + RESPONSE + "\r\u001b[2K\r" + COMPLETED)
        .replace("[INF]", "[\u001b[34mINF\u001b[0m]");
    assertThat(completedResult(log).data()).containsEntry("executionVerified", true);
  }

  @Test
  void doesNotLoseReportedFindingsWhenTheFileIsMissing() {
    assertThatThrownBy(() -> completedResult(STARTED + RESPONSE + COMPLETED.replace("found=0", "found=1")))
        .isInstanceOf(ApiException.class).hasMessageContaining("结果文件缺失");
  }

  @Test
  void rejectsResultFileThatDisagreesWithReportedFindings() throws Exception {
    Files.writeString(work.resolve("result.json"), "[]");
    assertThatThrownBy(() -> completedResult(STARTED + RESPONSE + COMPLETED.replace("found=0", "found=1")))
        .isInstanceOf(ApiException.class).hasMessageContaining("不一致");
  }

  @Test
  void acceptsActualAfrogThreeResultFormatWithVerifiedCompletion() throws Exception {
    Files.writeString(work.resolve("result.json"), """
        [{"isvul":true,"target":"https://127.0.0.1:8443/",
          "fulltarget":"https://127.0.0.1:8443/fixture",
          "pocinfo":{"id":"afrog-test-poc","infoname":"Local fixture","infoseg":"info"}}]
        """);
    ToolExecutionResult result = completedResult(STARTED + RESPONSE + COMPLETED.replace("found=0", "found=1"));

    assertThat(result.findings()).hasSize(1);
    assertThat(result.data()).containsEntry("matchCount", 1).containsEntry("executionVerified", true);
  }

  @Test
  void rejectsAnExistingButEmptyResultFile() throws Exception {
    Files.writeString(work.resolve("result.json"), "");
    assertThatThrownBy(() -> completedResult(STARTED + RESPONSE + COMPLETED))
        .isInstanceOf(ApiException.class).hasMessageContaining("结果为空");
  }

  @Test
  void returnsCancellationTypeAndTerminatesProcess() throws Exception {
    Process process = mock(Process.class);
    when(process.getInputStream()).thenReturn(new ByteArrayInputStream(new byte[0]));
    when(process.isAlive()).thenReturn(true);
    ToolExecutionObserver observer = new ToolExecutionObserver() {
      @Override public boolean isCancellationRequested() { return true; }
    };

    assertThatThrownBy(() -> tool.waitFor(process, observer, "test"))
        .isInstanceOf(CancellationException.class);
    verify(process).destroyForcibly();
  }

  @Test
  void returnsTimeoutTypeInsteadOfGenericFailure() throws Exception {
    Process process = mock(Process.class);
    when(process.getInputStream()).thenReturn(new ByteArrayInputStream(new byte[0]));
    when(process.waitFor(250, TimeUnit.MILLISECONDS)).thenReturn(false);
    AfrogScanTool immediateTimeout = new AfrogScanTool(mock(TargetPolicyService.class),
        new ObjectMapper(), mock(ScannerPocSelectionService.class), "afrog", 0);

    assertThatThrownBy(() -> immediateTimeout.waitFor(process, ToolExecutionObserver.NOOP, "test"))
        .isInstanceOf(TimeoutException.class);
    verify(process).destroyForcibly();
  }

  @ParameterizedTest
  @NullAndEmptySource
  @ValueSource(strings = {" ", "null", "{}", "true", "42", "[null]", "[{}]", "[1]",
      "{\"error\":\"failed\"}", "{\"results\":[],\"error\":\"failed\"}",
      "{\"results\":[],\"success\":false}", "{\"results\":null}", "{\"results\":{}}",
      "[] {}", "[] trailing", "[", "{\"results\":[],\"results\":[]}"})
  void rejectsMalformedOrUnknownResultsInsteadOfReportingNoFindings(String json) {
    assertThatThrownBy(() -> tool.parseOutput(
        URI.create("https://127.0.0.1:8443"), List.of(poc("afrog-test-poc")), json))
        .isInstanceOf(ApiException.class);
  }

  private String summarize(String raw) throws Exception {
    return tool.readExecutionEvidence(new BufferedReader(new StringReader(raw)));
  }

  private ToolExecutionResult completedResult(String raw) throws Exception {
    return tool.parseCompletedOutput(URI.create("https://127.0.0.1:8443"),
        List.of(poc("afrog-test-poc")), work.resolve("result.json"), summarize(raw));
  }

  private ScannerPocSelectionService.SelectedPoc poc(String externalId) {
    return new ScannerPocSelectionService.SelectedPoc(
        "AP-1234567890ABCDEF12345678",
        externalId,
        "Afrog issue",
        "HIGH",
        Path.of("poc.yaml"),
        "0".repeat(64));
  }
}
