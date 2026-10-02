package com.bachelor.toolbox.tool;

import static org.assertj.core.api.Assertions.assertThat;

import com.bachelor.toolbox.dependency.NmapExecutableResolver;
import com.bachelor.toolbox.target.PortRangeParser;
import com.bachelor.toolbox.target.TargetPolicyService;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class NmapServiceScanToolTests {
  @TempDir Path tempDir;

  @Test
  void usesNmapFullRangeFlagInsteadOfEnumeratingPorts() throws Exception {
    NmapServiceScanTool tool = toolWithExecutable(createExecutable("nmap.exe"));
    List<String> command = tool.buildCommand("127.0.0.1", "1-65535", "quick");

    assertThat(command).contains("-p-").doesNotContain("1-65535", "-p");
  }

  @Test
  void passesOtherSelectionsAsOneCompactRangeArgument() throws Exception {
    NmapServiceScanTool tool = toolWithExecutable(createExecutable("nmap.exe"));
    List<String> command = tool.buildCommand("127.0.0.1", "80-82,443", "service");

    assertThat(command)
        .containsSubsequence("-sV", "--version-light")
        .containsSubsequence("--stats-every", "1s")
        .containsSubsequence("-p", "80-82,443");
  }

  @Test
  void resolvesConfiguredCommandNameBeforeCheckingExecutableFile() throws Exception {
    Path resolvedExecutable = createExecutable("nmap-from-path.exe");
    AtomicReference<List<String>> receivedCandidates = new AtomicReference<>();
    NmapExecutableResolver resolver =
        new NmapExecutableResolver(
            candidates -> {
              receivedCandidates.set(candidates);
              return Optional.of(resolvedExecutable);
            },
            "nmap");
    NmapServiceScanTool tool = tool(resolver);

    List<String> command = tool.buildCommand("127.0.0.1", "443", "quick");

    // configured "nmap" duplicates the first fallback, so the resolver deduplicates it.
    assertThat(receivedCandidates.get()).containsExactly("nmap", "nmap.exe");
    assertThat(command.get(0)).isEqualTo(resolvedExecutable.normalize().toString());
  }

  @Test
  void serializesExplicitPortEvidenceWhileKeepingOpenPortsAssetContract() throws Exception {
    NmapServiceScanTool tool = toolWithExecutable(createExecutable("nmap.exe"));
    ToolExecutionResult result = tool.parseResult("""
        <nmaprun><host><status state="up" reason="user-set"/><ports>
          <port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/>
            <service name="ssh" product="OpenSSH"/></port>
          <port protocol="tcp" portid="80"><state state="closed" reason="conn-refused"/></port>
          <port protocol="tcp" portid="443"><state state="filtered" reason="no-response"/></port>
        </ports></host></nmaprun>
        """, "127.0.0.1", "service", "22,80,443", 3, 0);
    var json = new ObjectMapper().valueToTree(result);
    var data = json.path("data");

    assertThat(data.path("requestedPorts").asText()).isEqualTo("22,80,443");
    assertThat(data.path("requestedPortCount").asInt()).isEqualTo(3);
    assertThat(data.path("openPorts").size()).isEqualTo(1);
    var open = data.path("openPorts").get(0);
    assertThat(open.path("port").asInt()).isEqualTo(22);
    assertThat(open.path("state").asText()).isEqualTo("open");
    assertThat(open.path("service").asText()).isEqualTo("ssh");
    assertThat(open.path("assessmentType").asText()).isEqualTo("ASSET_OBSERVATION");
    assertThat(open.path("vulnerability").asBoolean()).isFalse();
    assertThat(data.path("portStates").size()).isEqualTo(3);
    assertThat(data.path("portStates").get(1).path("state").asText()).isEqualTo("closed");
    assertThat(data.path("portStates").get(2).path("state").asText()).isEqualTo("filtered");
    assertThat(data.path("portStates").get(2).path("reason").asText()).isEqualTo("no-response");
    assertThat(data.path("hostStatuses").get(0).path("reason").asText()).isEqualTo("user-set");
    assertThat(data.path("rawSummary").path("exitCode").asInt()).isZero();
    assertThat(data.path("rawSummary").path("openPortCount").asInt()).isEqualTo(1);
    assertThat(result.findings()).isEmpty();
  }

  @Test
  void doesNotMapAggregateCountsToRequestedPortsWithoutXmlEvidence() throws Exception {
    NmapServiceScanTool tool = toolWithExecutable(createExecutable("nmap.exe"));
    ToolExecutionResult result = tool.parseResult("""
        <nmaprun><host><ports>
          <extraports state="closed" count="1"><extrareasons reason="reset" count="1"/></extraports>
          <extraports state="filtered" count="1"><extrareasons reason="no-response" count="1"/></extraports>
        </ports></host></nmaprun>
        """, "127.0.0.1", "quick", "80,443", 2, 0);
    var data = new ObjectMapper().valueToTree(result).path("data");

    assertThat(data.path("portStates").isEmpty()).isTrue();
    assertThat(data.path("openPorts").isEmpty()).isTrue();
    assertThat(data.path("extraports").size()).isEqualTo(2);
    assertThat(data.path("extraports").get(0).path("state").asText()).isEqualTo("closed");
    assertThat(data.path("extraports").get(1).path("state").asText()).isEqualTo("filtered");
    assertThat(data.path("extraports").get(0).path("reasons").get(0).has("ports")).isFalse();
    assertThat(data.path("extraports").get(1).path("reasons").get(0).has("ports")).isFalse();
    assertThat(data.path("evidenceNote").asText()).contains("不能推断为 closed", "历史结果", "filtered");
  }

  @Test
  void preservesHostDownWithoutClaimingEveryRequestedPortWasObserved() throws Exception {
    NmapServiceScanTool tool = toolWithExecutable(createExecutable("nmap.exe"));
    ToolExecutionResult result = tool.parseResult("""
        <nmaprun><host><status state="down" reason="no-response"/></host></nmaprun>
        """, "192.0.2.1", "quick", "80,443", 2, 0);
    var data = new ObjectMapper().valueToTree(result).path("data");

    assertThat(data.path("hostStatuses").get(0).path("state").asText()).isEqualTo("down");
    assertThat(data.path("portStates").isEmpty()).isTrue();
    assertThat(data.path("extraports").isEmpty()).isTrue();
    assertThat(result.summary()).contains("2 个授权端口的扫描请求", "记录 0 个开放端口");
    assertThat(result.findings()).isEmpty();
  }

  private NmapServiceScanTool toolWithExecutable(Path executable) {
    return tool(new NmapExecutableResolver(candidates -> Optional.of(executable), "nmap"));
  }

  private NmapServiceScanTool tool(NmapExecutableResolver resolver) {
    return new NmapServiceScanTool(
        new TargetPolicyService(false, new PortRangeParser()),
        new PortRangeParser(),
        resolver,
        65535,
        60,
        600);
  }

  private Path createExecutable(String name) throws Exception {
    return Files.createFile(tempDir.resolve(name));
  }
}
