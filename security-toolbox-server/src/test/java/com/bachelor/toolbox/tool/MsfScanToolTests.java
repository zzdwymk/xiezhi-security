package com.bachelor.toolbox.tool;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

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
    assertThat(script).endsWith("run; exit").doesNotContain(" -j", "sleep 2", "jobs -k");
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
    assertThat(script).endsWith("check; exit");
    assertThat(script).doesNotContain("run", " -j", "sleep 2", "jobs -k");
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

  @Test
  void zeroConsoleExitCannotHideModuleFailure() {
    assertThatThrownBy(() -> tool.requireSuccessfulConsoleOutput("[-] Auxiliary failed: Msf::OptionValidateError RHOSTS"))
        .isInstanceOf(com.bachelor.toolbox.common.ApiException.class);
    tool.requireSuccessfulConsoleOutput("[+] 127.0.0.1:80 Header: value\n[*] Auxiliary module execution completed");
  }

  @Test
  void httpHeaderPositiveLinesAreRawObservationsNotLowSeverityVulnerabilities() {
    ToolExecutionResult result = tool.parseOutput("192.168.1.7", "auxiliary/scanner/http/http_header",
        "[+] 192.168.1.7:80 SERVER: nginx\n[+] 192.168.1.7:80 X-POWERED-BY: example\n"
            + "[+] 192.168.1.7:80 detected 2 headers\n[+] 10.0.0.9:80 SERVER: out-of-scope\n");
    assertThat(result.findings()).isEmpty();
    assertThat(result.data()).containsEntry("matchCount", 0).containsEntry("observationCount", 3);
    assertThat(result.data().get("observations")).asList().allSatisfy(observation -> {
      assertThat(((Map<?, ?>) observation).get("assessmentType")).isEqualTo("ASSET_OBSERVATION");
      assertThat(((Map<?, ?>) observation).get("vulnerability")).isEqualTo(false);
    });
    assertThat(result.data().get("observations").toString()).contains("SERVER: nginx").doesNotContain("out-of-scope");
  }

  @Test
  void waitsForRealProcessCompletionAndPropagatesTimeoutWithoutNetwork() throws Exception {
    Process completed = fixtureProcess("complete");
    try {
      assertThat(tool.waitFor(completed, ToolExecutionObserver.NOOP, "fixture")).contains("fixture complete");
      assertThat(completed.isAlive()).isFalse();
    } finally { completed.destroyForcibly(); }
    MsfScanTool shortTimeout = new MsfScanTool(new TargetPolicyService(false, new PortRangeParser()),
        candidates -> java.util.Optional.empty(), "unused", 1, null);
    Process sleeping = fixtureProcess("wait");
    try {
      assertThatThrownBy(() -> shortTimeout.waitFor(sleeping, ToolExecutionObserver.NOOP, "fixture"))
          .isInstanceOf(java.util.concurrent.TimeoutException.class);
      assertThat(sleeping.isAlive()).isFalse();
    } finally { sleeping.destroyForcibly(); }
  }

  private Process fixtureProcess(String mode) throws Exception {
    String java = Path.of(System.getProperty("java.home"), "bin", "java").toString();
    return new ProcessBuilder(java, "-cp", System.getProperty("java.class.path"),
        ProcessFixture.class.getName(), mode).redirectErrorStream(true).start();
  }

  @Test
  void oversizedOutputFailsPromptlyInsteadOfWaitingForScannerTimeout() throws Exception {
    Process verbose = fixtureProcess("oversized");
    try {
      org.junit.jupiter.api.Assertions.assertTimeoutPreemptively(java.time.Duration.ofSeconds(10), () ->
          assertThatThrownBy(() -> tool.waitFor(verbose, ToolExecutionObserver.NOOP, "fixture"))
              .hasRootCauseInstanceOf(com.bachelor.toolbox.common.ApiException.class)
              .hasRootCauseMessage("Metasploit 输出超过安全大小限制"));
      verbose.waitFor(5, java.util.concurrent.TimeUnit.SECONDS);
      assertThat(verbose.isAlive()).isFalse();
    } finally { verbose.destroyForcibly(); }
  }

  @Test
  void cancellationStopsTheActualProcessTreeInsteadOfLeavingScannerChildren() throws Exception {
    Process parent = fixtureProcess("parent");
    List<ProcessHandle> children = List.of();
    try {
      long deadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(10);
      while (children.isEmpty() && System.nanoTime() < deadline) {
        children = parent.descendants().toList();
        Thread.sleep(50);
      }
      assertThat(children).hasSize(1);
      assertThatThrownBy(() -> tool.waitFor(parent, new ToolExecutionObserver() {
        @Override public boolean isCancellationRequested() { return true; }
      }, "fixture")).isInstanceOf(com.bachelor.toolbox.common.ApiException.class).hasMessage("任务已取消");
      assertThat(parent.isAlive()).isFalse();
      for (ProcessHandle child : children) {
        child.onExit().get(5, java.util.concurrent.TimeUnit.SECONDS);
        assertThat(child.isAlive()).isFalse();
      }
    } finally {
      children.forEach(ProcessHandle::destroyForcibly);
      parent.destroyForcibly();
    }
  }

  public static class ProcessFixture {
    public static void main(String[] args) throws Exception {
      if ("oversized".equals(args[0])) {
        byte[] block = new byte[64 * 1024];
        for (int index = 0; index < 128; index++) System.out.write(block);
        System.out.flush();
        Thread.sleep(30000);
        return;
      }
      if ("parent".equals(args[0])) {
        String java = Path.of(System.getProperty("java.home"), "bin", "java").toString();
        Process child = new ProcessBuilder(java, "-cp", System.getProperty("java.class.path"),
            ProcessFixture.class.getName(), "wait").start();
        child.waitFor();
        return;
      }
      Thread.sleep("wait".equals(args[0]) ? 30000 : 500);
      System.out.println("fixture complete");
    }
  }
}
