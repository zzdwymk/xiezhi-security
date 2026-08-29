package com.bachelor.toolbox.tool;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import com.bachelor.toolbox.target.PortRangeParser;
import com.bachelor.toolbox.target.TargetPolicyService;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;

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

    assertThat(command).contains("-np", "-nopoc", "-nobr", "-nofuzz");
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
  void ignoresOutOfScopeHostRiskLines() {
    String output = "start\n[+] [Vuln] 192.0.2.50:445 SMB 漏洞\n";

    ToolExecutionResult result = tool.parseOutput("127.0.0.1", "80", output);

    assertThat(result.findings()).isEmpty();
  }
}