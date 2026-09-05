package com.bachelor.toolbox.tool;

import static org.assertj.core.api.Assertions.assertThat;

import com.bachelor.toolbox.msf.MsfScanEngine;
import com.bachelor.toolbox.target.PortRangeParser;
import com.bachelor.toolbox.target.TargetPolicyService;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class MsfScanToolTests {
  private final MsfScanTool tool =
      new MsfScanTool(
          new TargetPolicyService(false, new PortRangeParser()),
          candidates -> java.util.Optional.of(Path.of("msfconsole.exe")),
          "msfconsole",
          600,
          new org.springframework.beans.factory.ObjectProvider<MsfScanEngine>() {
            @Override
            public MsfScanEngine getObject() {
              return null;
            }

            @Override
            public MsfScanEngine getObject(Object... args) {
              return null;
            }
          });

  @Test
  void buildCommandForcesAuthorizedHostAndRunsAuxiliary() {
    List<String> command =
        tool.buildCommand(
            Path.of("msfconsole.exe"),
            "192.168.1.5",
            "auxiliary/scanner/ssh/ssh_login",
            Map.of("USERNAME", "root", "THREADS", "4"));

    assertThat(command.get(0)).isEqualTo("msfconsole.exe");
    assertThat(command).contains("-q", "-x");
    String script = command.get(command.size() - 1);
    assertThat(script).startsWith("use auxiliary/scanner/ssh/ssh_login;");
    assertThat(script).contains("setg RHOSTS 192.168.1.5;");
    assertThat(script).contains("set USERNAME root;");
    assertThat(script).contains("set THREADS 4;");
    assertThat(script).contains("run -j;");
  }

  @Test
  void buildCommandForExploitUsesCheckInsteadOfRun() {
    List<String> command =
        tool.buildCommand(
            Path.of("msfconsole.exe"),
            "192.168.1.7",
            "exploit/multi/script/web_delivery",
            new HashMap<>());

    String script = command.get(command.size() - 1);
    assertThat(script).contains("check -j;");
    assertThat(script).doesNotContain("run -j;");
  }

  @Test
  void parseOutputKeepsOnlyPositiveHitsWithinAuthorizedHost() {
    String output =
        "[*] using exploit modules\n"
            + "[+] 192.168.1.7:22 - SSH - Success: 'root:toor' at 2026-01-01\n"
            + "[-] 192.168.1.7:22 - No response\n"
            + "[+] 10.0.0.9:22 - SSH - Success: out of scope\n"
            + "[*] finishing\n";

    ToolExecutionResult result =
        tool.parseOutput("192.168.1.7", "auxiliary/scanner/ssh/ssh_login", output);

    assertThat(result.summary()).contains("1");
    assertThat(result.findings()).hasSize(1);
    assertThat(result.findings().get(0).description()).contains("ssh_login");
    @SuppressWarnings("unchecked")
    List<Map<String, Object>> matches =
        (List<Map<String, Object>>)
            ((java.util.Map<String, Object>) result.data()).get("matches");
    assertThat(matches).hasSize(1);
  }
}