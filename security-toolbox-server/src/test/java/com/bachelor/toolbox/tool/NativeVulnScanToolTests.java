package com.bachelor.toolbox.tool;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.PortRangeParser;
import com.bachelor.toolbox.target.TargetPolicyService;
import com.bachelor.toolbox.vulnerability.HostPluginCatalogService;
import com.bachelor.toolbox.vulnerability.HostPluginParser;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class NativeVulnScanToolTests {
  @TempDir Path root;

  private AuthorizedTarget target() {
    AuthorizedTarget target = new AuthorizedTarget();
    target.setName("靶场");
    target.setTargetValue("192.168.1.10");
    target.setTargetType("IP");
    target.setAllowedPorts("80,443");
    target.setAuthorizationNote("测试授权");
    target.setEnabled(true);
    return target;
  }

  private ScannerPocSelectionService.SelectedPoc poc(Path file) {
    return new ScannerPocSelectionService.SelectedPoc(
        "HP-" + "A".repeat(24), "plugin-1", "插件", "INFO", file, "sha");
  }

  private NativeVulnScanTool tool(ScannerPocSelectionService selection, NativeVulnScanTool.BannerProber prober) {
    return new NativeVulnScanTool(
        new TargetPolicyService(false, new PortRangeParser()),
        new PortRangeParser(),
        selection,
        new HostPluginParser(new ObjectMapper()),
        prober,
        60);
  }

  @Test
  void refusesBlockedPluginWithoutExecuting() throws Exception {
    Path file = root.resolve("blocked.json");
    Files.writeString(
        file,
        """
        {"pluginID":"1","pluginName":"Redis 未授权","scan_safety":"BLOCKED"}
        """,
        StandardCharsets.UTF_8);
    ScannerPocSelectionService selection = mock(ScannerPocSelectionService.class);
    when(selection.resolve(any(), any(), any())).thenReturn(List.of(poc(file)));
    NativeVulnScanTool tool = tool(selection, (host, port) -> new NativeVulnScanTool.ProbeResult(true, "banner"));

    ToolExecutionResult result = tool.execute(target(), Map.of());

    assertThat(result.findings()).isEmpty();
    assertThat(result.data().get("skipped"))
        .asList()
        .extracting(Object::toString)
        .anyMatch(s -> s.contains("拒绝自动执行"));
  }

  @Test
  void safePluginWithReachableAuthorizedPortProducesFinding() throws Exception {
    Path file = root.resolve("safe.json");
    Files.writeString(
        file,
        """
        {"pluginID":"2","pluginName":"Http 弱指纹","protocols":["http"],
         "risk_information":{"cvss_base_score":0.0,"risk":"Info"},"scan_safety":"SAFE"}
        """,
        StandardCharsets.UTF_8);
    ScannerPocSelectionService selection = mock(ScannerPocSelectionService.class);
    when(selection.resolve(any(), any(), any())).thenReturn(List.of(poc(file)));
    NativeVulnScanTool tool =
        tool(selection, (host, port) -> new NativeVulnScanTool.ProbeResult(true, "nginx/1.18"));

    ToolExecutionResult result = tool.execute(target(), Map.of());

    assertThat(result.data().get("observationCount")).isEqualTo(1);
    assertThat(result.data().get("matchCount")).isEqualTo(1);
  }
}