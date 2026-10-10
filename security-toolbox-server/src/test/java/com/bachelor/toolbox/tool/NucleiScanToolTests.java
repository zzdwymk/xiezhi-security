package com.bachelor.toolbox.tool;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

import com.bachelor.toolbox.target.PortRangeParser;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.TargetPolicyService;
import com.bachelor.toolbox.target.WebTargetResolver;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class NucleiScanToolTests {
  private final NucleiScanTool tool =
      new NucleiScanTool(
          mock(TargetPolicyService.class),
          new PortRangeParser(),
          new ObjectMapper(),
          "nuclei",
          ".",
          65535,
          60);

  @Test
  void buildsBoundedAuthorizedCommand() {
    Path targetList = Path.of("authorized-targets.txt");

    List<String> command = tool.buildCommand(targetList);

    assertThat(command).containsSubsequence("-list", targetList.toString(), "-pt", "http,ssl");
    List<String> templates = new ArrayList<>();
    for (int i = 0; i < command.size() - 1; i++) {
      if ("-templates".equals(command.get(i))) {
        templates.add(command.get(i + 1));
      }
    }
    assertThat(templates).hasSize(4);
    assertThat(templates.get(0)).endsWith(Path.of("http", "exposures").toString());
    assertThat(templates.get(1)).endsWith(Path.of("http", "misconfiguration").toString());
    assertThat(templates.get(2)).endsWith(Path.of("http", "technologies").toString());
    assertThat(templates.get(3)).endsWith(Path.of("ssl").toString());
    assertThat(command).contains("-jsonl", "-duc", "-dr", "-ni", "-dut", "-or", "-ot");
    assertThat(command).containsSubsequence("-stats-json", "-si", "1");
    assertThat(command).contains("-etags");
    assertThat(command.get(command.indexOf("-etags") + 1))
        .contains("intrusive", "bruteforce", "rce", "sqli");
    assertThat(command).doesNotContain("-port");
    assertThat(command).doesNotContain("-headless", "-code", "-tags", "-include-tags");
  }

  @Test
  void bareHostUsesOneSchemeNegotiatedTargetPerAuthorizedPort() {
    AuthorizedTarget target = new AuthorizedTarget();
    target.setTargetValue("127.0.0.1");
    assertThat(tool.targetEntries(target, "127.0.0.1", "8080,8443", Map.of()))
        .containsExactly("127.0.0.1:8080", "127.0.0.1:8443");
  }

  @Test
  void usesOnlyResolvedWebAddressesWhenAvailable() {
    AuthorizedTarget target = new AuthorizedTarget();
    target.setTargetValue("127.0.0.1");
    assertThat(tool.targetEntries(target, "127.0.0.1", "8080,8443",
        Map.of(WebTargetResolver.PARAM_RESOLVED_BASES, List.of("https://127.0.0.1:8443/app"))))
        .containsExactly("https://127.0.0.1:8443/app");
  }

  @ParameterizedTest
  @ValueSource(strings = {"http://192.0.2.1:8080/", "http://127.0.0.1:9999/",
      "ftp://127.0.0.1:8080/", "http://secret@127.0.0.1:8080/", "not a uri"})
  void refusesResolvedAddressesOutsideAuthorizationOrWithInvalidFormat(String base) {
    AuthorizedTarget target = new AuthorizedTarget();
    target.setTargetValue("127.0.0.1");
    assertThatThrownBy(() -> tool.targetEntries(target, "127.0.0.1", "8080",
        Map.of(WebTargetResolver.PARAM_RESOLVED_BASES, List.of(base))))
        .isInstanceOf(com.bachelor.toolbox.common.ApiException.class);
  }

  @Test
  void parsesJsonLinesIntoFindings() {
    String jsonl =
        """
{"template-id":"CVE-2025-0001","info":{"name":"Example issue","severity":"high"},"matched-at":"http://127.0.0.1:8080"}
non-json diagnostic
""";

    ToolExecutionResult result = tool.parseOutput("127.0.0.1", "8080", jsonl);

    assertThat(result.findings()).hasSize(1);
    assertThat(result.findings().get(0).severity()).isEqualTo("HIGH");
    assertThat(result.findings().get(0).evidence())
        .contains("CVE-2025-0001")
        .contains("127.0.0.1:8080");
    assertThat(result.findings().get(0).vulnerabilityCode()).startsWith("NT-");
    assertThat(result.data()).containsEntry("matchCount", 1);
  }

  @Test
  void rejectsOutOfScopeNucleiMatchInsteadOfIgnoringIt() {
    String jsonl =
        """
{"template-id":"real-template","info":{"name":"Example","severity":"high"},"matched-at":"http://192.0.2.10:8080"}
""";

    assertThatThrownBy(() -> tool.parseOutput("127.0.0.1", "8080", jsonl))
        .isInstanceOf(com.bachelor.toolbox.common.ApiException.class)
        .hasMessageContaining("授权范围外");
  }

  @Test
  void deadlineIsReportedAsTimeoutAndStopsLocalProcessWithoutNetwork() throws Exception {
    NucleiScanTool bounded = new NucleiScanTool(mock(TargetPolicyService.class),
        new PortRangeParser(), new ObjectMapper(), "unused", ".", 1, 1);
    Process process = fixtureProcess("wait");
    try {
      assertThatThrownBy(() -> bounded.waitFor(process, ToolExecutionObserver.NOOP))
          .isInstanceOf(java.util.concurrent.TimeoutException.class)
          .hasMessageContaining("超过 1 秒");
      assertThat(process.isAlive()).isFalse();
    } finally { process.destroyForcibly(); }
  }

  @Test
  void realCompletionAndUserCancellationRemainDistinct() throws Exception {
    Process completed = fixtureProcess("complete");
    try {
      assertThat(tool.waitFor(completed, ToolExecutionObserver.NOOP)).contains("fixture complete");
    } finally { completed.destroyForcibly(); }
    Process cancelled = fixtureProcess("wait");
    try {
      assertThatThrownBy(() -> tool.waitFor(cancelled, new ToolExecutionObserver() {
        @Override public boolean isCancellationRequested() { return true; }
      })).isInstanceOf(com.bachelor.toolbox.common.ApiException.class).hasMessage("任务已取消");
      assertThat(cancelled.isAlive()).isFalse();
    } finally { cancelled.destroyForcibly(); }
  }

  @Test
  void timeoutRetainsValidMatchesAndDiscardsTruncatedJsonWithoutReportingCompletion() throws Exception {
    Process process = fixtureProcess("partial");
    List<Double> percentages = new ArrayList<>();
    try {
      assertThatThrownBy(() -> boundedTool().executeProcess(process, "127.0.0.1", "8080", new ToolExecutionObserver() {
        @Override public void progressPercent(double percentage, String operation) { percentages.add(percentage); }
      })).isInstanceOfSatisfying(ToolExecutionTimeoutException.class, failure -> {
        ToolExecutionResult partial = failure.partialResult();
        assertThat(partial.summary()).contains("超时", "未完整完成", "不能判断为无风险");
        assertThat(partial.data()).containsEntry("partial", true).containsEntry("scanCompleted", false)
            .containsEntry("terminationReason", "TIMEOUT").containsEntry("matchCount", 1);
        assertThat(partial.findings()).hasSize(1);
        assertThat(partial.findings().get(0).severity()).isEqualTo("HIGH");
        assertThat(partial.findings().get(0).evidence()).contains("observed-template", "127.0.0.1:8080");
        assertThat(partial.findings().get(0).vulnerabilityCode()).startsWith("NT-");
      });
      assertThat(process.isAlive()).isFalse();
      assertThat(percentages).doesNotContain(100d);
    } finally { process.destroyForcibly(); }
  }

  @Test
  void timeoutWithoutMatchesRemainsExplicitlyIncomplete() throws Exception {
    Process process = fixtureProcess("wait");
    try {
      assertThatThrownBy(() -> boundedTool().executeProcess(process, "127.0.0.1", "8080", ToolExecutionObserver.NOOP))
          .isInstanceOfSatisfying(ToolExecutionTimeoutException.class, failure -> {
            assertThat(failure.partialResult().findings()).isEmpty();
            assertThat(failure.partialResult().data()).containsEntry("matchCount", 0).containsEntry("scanCompleted", false);
            assertThat(failure.partialResult().summary()).contains("不能判断为无风险");
          });
    } finally { process.destroyForcibly(); }
  }

  @ParameterizedTest
  @ValueSource(strings = {"outside-host", "outside-port", "outside-after-limit"})
  void timeoutDoesNotRetainAnyOutputContainingAnOutOfScopeMatch(String mode) throws Exception {
    Process process = fixtureProcess(mode);
    try {
      assertThatThrownBy(() -> boundedTool().executeProcess(process, "127.0.0.1", "8080", ToolExecutionObserver.NOOP))
          .isInstanceOf(com.bachelor.toolbox.common.ApiException.class)
          .isNotInstanceOf(ToolExecutionTimeoutException.class)
          .hasMessageContaining("授权范围外");
      assertThat(process.isAlive()).isFalse();
    } finally { process.destroyForcibly(); }
  }

  @Test
  void timeoutRetainsOnlyBoundedFindingsAndMarksTruncation() throws Exception {
    Process process = fixtureProcess("many");
    try {
      assertThatThrownBy(() -> boundedTool().executeProcess(process, "127.0.0.1", "8080", ToolExecutionObserver.NOOP))
          .isInstanceOfSatisfying(ToolExecutionTimeoutException.class, failure -> {
            assertThat(failure.partialResult().findings()).hasSize(500);
            assertThat(failure.partialResult().data()).containsEntry("matchCount", 501).containsEntry("truncated", true);
          });
    } finally { process.destroyForcibly(); }
  }

  @Test
  void cancellationAfterMatchDoesNotBecomePartialTimeout() throws Exception {
    Process process = fixtureProcess("partial");
    AtomicBoolean observed = new AtomicBoolean();
    try {
      assertThatThrownBy(() -> tool.executeProcess(process, "127.0.0.1", "8080", new ToolExecutionObserver() {
        @Override public void heartbeat(String operation) {
          if (operation.contains("模板匹配结果")) observed.set(true);
        }
        @Override public boolean isCancellationRequested() { return observed.get(); }
      })).isInstanceOf(com.bachelor.toolbox.common.ApiException.class)
          .isNotInstanceOf(ToolExecutionTimeoutException.class).hasMessage("任务已取消");
      assertThat(observed).isTrue();
      assertThat(process.isAlive()).isFalse();
    } finally { process.destroyForcibly(); }
  }

  @Test
  void nonzeroExitAfterMatchDoesNotBecomeSuccessfulOrPartialTimeout() throws Exception {
    Process process = fixtureProcess("failure");
    try {
      assertThatThrownBy(() -> tool.executeProcess(process, "127.0.0.1", "8080", ToolExecutionObserver.NOOP))
          .isInstanceOf(com.bachelor.toolbox.common.ApiException.class)
          .isNotInstanceOf(ToolExecutionTimeoutException.class).hasMessageContaining("退出码 4");
    } finally { process.destroyForcibly(); }
  }

  @ParameterizedTest
  @ValueSource(strings = {"outcome-empty", "outcome-no-requests", "outcome-all-failed",
      "outcome-partly-failed", "outcome-no-templates", "outcome-missing-errors", "outcome-broken-json"})
  void zeroExitWithoutSuccessfulExecutionEvidenceCannotBecomeNoFindings(String mode) throws Exception {
    Process process = fixtureProcess(mode);
    List<String> operations = new ArrayList<>();
    try {
      assertThatThrownBy(() -> tool.executeProcess(process, "127.0.0.1", "8080", new ToolExecutionObserver() {
        @Override public void progressPercent(double percentage, String operation) { operations.add(operation); }
      })).isInstanceOf(com.bachelor.toolbox.common.ApiException.class)
          .hasMessageContaining("Nuclei");
      assertThat(process.exitValue()).isZero();
      // Native progress may say 100 even though all requests failed; never emit a
      // separate completed operation until execution evidence has been checked.
      assertThat(operations).doesNotContain("Nuclei 扫描完成，正在解析匹配结果");
    } finally { process.destroyForcibly(); }
  }

  @Test
  void validCompletedRequestStatisticsAllowARealNegativeResult() throws Exception {
    Process process = fixtureProcess("outcome-success");
    try {
      ToolExecutionResult result = tool.executeProcess(process, "127.0.0.1", "8080", ToolExecutionObserver.NOOP);
      assertThat(result.findings()).isEmpty();
      assertThat(result.data()).containsEntry("matchCount", 0);
    } finally { process.destroyForcibly(); }
  }

  private NucleiScanTool boundedTool() {
    return new NucleiScanTool(mock(TargetPolicyService.class), new PortRangeParser(),
        new ObjectMapper(), "unused", ".", 65535, 1);
  }

  private Process fixtureProcess(String mode) throws Exception {
    String java = Path.of(System.getProperty("java.home"), "bin", "java").toString();
    return new ProcessBuilder(java, "-cp", System.getProperty("java.class.path"),
        ProcessFixture.class.getName(), mode).redirectErrorStream(true).start();
  }

  public static class ProcessFixture {
    public static void main(String[] args) throws Exception {
      String mode = args[0];
      if (mode.startsWith("outcome-")) {
        if ("outcome-empty".equals(mode)) return;
        String requests = "outcome-no-requests".equals(mode) ? "0" : "10";
        String errors = "outcome-all-failed".equals(mode) ? "10" : "outcome-partly-failed".equals(mode) ? "1" : "0";
        String templates = "outcome-no-templates".equals(mode) ? "0" : "2";
        System.out.println("{\"templates\":\"" + templates + "\",\"hosts\":\"1\",\"requests\":\"" + requests
            + "\",\"percent\":\"100\"" + ("outcome-missing-errors".equals(mode) ? "" : ",\"errors\":\"" + errors + "\"") + "}");
        if ("outcome-broken-json".equals(mode)) System.out.println("{\"template-id\":");
        return;
      }
      if (!"wait".equals(mode) && !"complete".equals(mode)) {
        int count = "many".equals(mode) ? 501 : "outside-after-limit".equals(mode) ? 500 : 1;
        for (int index = 0; index < count; index++) {
          System.out.println("{\"template-id\":\"observed-template\",\"info\":{\"name\":\"Observed issue\",\"severity\":\"high\"},\"matched-at\":\"http://127.0.0.1:8080/\"}");
        }
        if (mode.startsWith("outside")) {
          String url = "outside-port".equals(mode) ? "http://127.0.0.1:8081/" : "http://192.0.2.10:8080/";
          System.out.println("{\"template-id\":\"outside-template\",\"matched-at\":\"" + url + "\"}");
        }
        if ("partial".equals(mode)) {
          System.out.println("non-JSON diagnostic");
          System.out.print("{\"template-id\":\"incomplete");
        }
        System.out.flush();
        if ("failure".equals(mode)) System.exit(4);
      }
      Thread.sleep("complete".equals(mode) ? 100 : 30000);
      System.out.println("fixture complete");
    }
  }
}
