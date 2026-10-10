package com.bachelor.toolbox.tool;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

import com.bachelor.toolbox.target.PortRangeParser;
import com.bachelor.toolbox.target.TargetPolicyService;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import com.bachelor.toolbox.common.ApiException;

class FscanScanToolTests {
  private final FscanScanTool tool =
      new FscanScanTool(
          new TargetPolicyService(false, new PortRangeParser()),
          new PortRangeParser(),
          candidates -> java.util.Optional.of(Path.of("fscan.exe")),
          "fscan",
          65535,
          600);

  @Test
  void passesHostAndCompactPortRange() {
    List<String> command = tool.buildCommand(Path.of("fscan.exe"), "127.0.0.1", "80,443", "SAFE");

    assertThat(command).containsSubsequence("-h", "127.0.0.1", "-p", "80,443");
  }

  @Test
  void safeModeDisablesPocBruteAndFuzz() {
    List<String> command = tool.buildCommand(Path.of("fscan.exe"), "127.0.0.1", "80", "SAFE");

    assertThat(command).contains("-np", "-nopoc", "-nobr").doesNotContain("-nofuzz");
  }

  @Test
  void fingerprintModeKeepsPocDisabledButAllowsBruteOff() {
    List<String> command =
        tool.buildCommand(Path.of("fscan.exe"), "127.0.0.1", "80", "FINGERPRINT");

    assertThat(command).contains("-nopoc").doesNotContain("-nobr");
  }

  @Test
  void enablesOutputFileCapture() {
    List<String> command =
        tool.buildCommand(Path.of("fscan.exe"), "127.0.0.1", "80", "SAFE", Path.of("out.txt"));

    assertThat(command).containsSubsequence("-o", "out.txt");
  }

  @Test
  void parsesOpenPortsAsAssetObservations() {
    String output =
        """
        start infol
        [*] 127.0.0.1  is alive
        [+] 127.0.0.1:80
        [+] 127.0.0.1:443
        """;

    ToolExecutionResult result = tool.parseOutput("127.0.0.1", "80,443", output);

    assertThat(result.findings()).isEmpty();
    assertThat(result.data()).containsEntry("openPortCount", 2);
    assertThat(result.data().get("openPorts"))
        .asList()
        .extracting(row -> String.valueOf(((java.util.Map<?, ?>) row).get("port")))
        .containsExactlyInAnyOrder("80", "443");
  }

  @Test
  void flagsScopedRiskLineAsFindingAndKeepsSeverity() {
    String line = "[+] [Redis] 127.0.0.1:6379 未授权访问";
    String output = "start\n" + line + "\n";

    ToolExecutionResult result = tool.parseOutput("127.0.0.1", "6379", output);

    assertThat(result.findings()).hasSize(1);
    assertThat(result.findings().get(0).title()).isEqualTo("疑似未授权访问");
    assertThat(result.findings().get(0).severity()).isEqualTo("MEDIUM");
    assertThat(result.findings().get(0).vulnerabilityCode()).startsWith("FSCAN-");
    assertThat(result.findings().get(0).evidence()).contains("127.0.0.1:6379");
  }

  @Test
  void readsNative221ResultFileWhenConsoleOmitsDefaultHttpPort() {
    String console = "[*] http://192.168.136.132 http [Product:nginx]\n"
        + "[+] http://192.168.136.132 code:200 title:SQL Injections\n"
        + "[*] 扫描任务完成，耗时 4.083s，已扫描 2 个目标\n";
    String resultFile = "# ===== 开放端口 =====\n192.168.136.132:80\n\n"
        + "# ===== 服务信息 =====\nhttp://192.168.136.132:80 [SQL Injections] 200 nginx\n";
    tool.validateExecutionOutput(console);
    var result = tool.parseOutput("192.168.136.132", "80", console + resultFile, resultFile);
    assertThat(result.data()).containsEntry("openPortCount", 1);
    assertThat(result.findings()).isEmpty();
    assertThat(result.data().get("openPorts")).asList()
        .extracting(row -> String.valueOf(((java.util.Map<?, ?>) row).get("port"))).containsExactly("80");
  }

  @Test
  void nativeFilePortsAreScopedDeduplicatedAndLimitedToTheirSection() {
    String resultFile = "192.168.136.132:443\n# ===== 开放端口 =====\n"
        + "192.168.136.132:80\n192.168.136.132:80\n192.168.136.133:80\n"
        + "192.168.136.132:8080\n192.168.136.132:443 connection refused\n"
        + "# ===== 服务信息 =====\n192.168.136.132:443\n";
    var result = tool.parseOutput("192.168.136.132", "80,443", "", resultFile);
    assertThat(result.data()).containsEntry("openPortCount", 1);
    assertThat(result.findings()).isEmpty();
    assertThat(tool.parseOutput("192.168.136.132", "80,443", resultFile).data())
        .containsEntry("openPortCount", 0);
  }

  @Test
  void ignoresOutOfScopeHostRiskLines() {
    String output = "start\n[+] [Vuln] 192.0.2.50:445 SMB 漏洞\n";

    ToolExecutionResult result = tool.parseOutput("127.0.0.1", "80", output);

    assertThat(result.findings()).isEmpty();
  }

  @ParameterizedTest
  @ValueSource(strings = {"80", "80,6379"})
  void referencesInsideHttpMetadataDoNotBecomeAdditionalOpenPorts(String allowed) {
    var result = tool.parseOutput("192.168.136.132", allowed,
        "[*] http://192.168.136.132:80 code:200 title:peer 192.168.136.132:6379");
    assertThat(result.data()).containsEntry("openPortCount", 1);
  }

  @ParameterizedTest
  @ValueSource(strings = {"title:connection refused", "Banner:(dial tcp)", "[Product:connection refused]"})
  void httpMetadataErrorWordsAreNotEngineConnectionFailures(String metadata) {
    String output = "[*] http://192.168.136.132:80 code:200 " + metadata
        + "\n[*] 扫描任务完成，耗时 4.083s，已扫描 2 个目标\n";
    tool.validateExecutionOutput(output);
    assertThat(tool.parseOutput("192.168.136.132", "80", output).data())
        .containsEntry("openPortCount", 1);
  }

  @Test
  void nativeFileRetainsTheExistingPortDetailLimit() {
    StringBuilder file = new StringBuilder("# ===== 开放端口 =====\n");
    for (int port = 1; port <= 20001; port++) file.append("192.168.136.132:").append(port).append('\n');
    assertThat(tool.parseOutput("192.168.136.132", "1-20001", "", file.toString()).data())
        .containsEntry("openPortCount", 20000);
  }

  @Test
  void actualOfflineFscanCompletionCannotBeReportedAsNoVulnerabilities() {
    String output = "[*] 扫描完成，发现 0 个开放端口\n[*] 扫描任务完成，耗时 4ms，已扫描 0 个目标\n";
    assertThatThrownBy(() -> tool.validateExecutionOutput(output)).isInstanceOf(ApiException.class)
        .hasMessageContaining("未发现可访问的目标服务").hasMessageContaining("无法判断是否存在漏洞");
  }

  @Test
  void actualOnlineFscanCompletionIsAccepted() {
    tool.validateExecutionOutput("[*] 扫描完成，发现 1 个开放端口\n[*] 扫描任务完成，耗时 3.048s，已扫描 2 个目标\n");
  }

  @Test
  void completionWithPartiallyFailedConnectionsIsNotACompleteVerdict() {
    String output = "[*] http://127.0.0.1:80 code:200\n[-] dial tcp 127.0.0.1:445: i/o timeout\n"
        + "[*] 扫描任务完成，耗时 3.048s，已扫描 2 个目标\n";
    assertThatThrownBy(() -> tool.validateExecutionOutput(output)).isInstanceOf(ApiException.class)
        .hasMessageContaining("本次检测不完整");
  }

  @ParameterizedTest
  @NullAndEmptySource
  @ValueSource(strings = {"Fscan 2.2.1", "[*] 扫描完成，发现 0 个开放端口", "flag provided but not defined"})
  void missingExecutionEvidenceDoesNotMeanSuccess(String output) {
    assertThatThrownBy(() -> tool.validateExecutionOutput(output)).isInstanceOf(ApiException.class)
        .hasMessageContaining("无法确认检测已完成");
  }

  @Test
  void failedConnectionsNeverBecomeOpenPortsOrVulnerabilities() {
    var result = tool.parseOutput("127.0.0.1", "445,6379", """
        [-] [Vuln] dial tcp 127.0.0.1:6379: connection refused
        [*] SMBInfo 127.0.0.1:445 SMBv1 连接失败
        """);
    assertThat(result.data()).containsEntry("openPortCount", 0);
    assertThat(result.findings()).isEmpty();
  }

  @Test
  void servicesAndRisksOutsideRequestedPortsCannotContaminateResults() {
    var result = tool.parseOutput("127.0.0.1", "80", """
        [+] [Vuln] 127.0.0.1:6379 未授权访问
        [+] SMBInfo 127.0.0.10:445 SMBv1 ref=127.0.0.1
        [*] http://127.0.0.1:80 code:200 title:Local fixture
        """);
    assertThat(result.data()).containsEntry("openPortCount", 1);
    assertThat(result.findings()).isEmpty();
  }
}
