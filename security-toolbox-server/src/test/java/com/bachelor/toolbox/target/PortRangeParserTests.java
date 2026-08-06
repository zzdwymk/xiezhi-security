package com.bachelor.toolbox.target;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.tool.TcpPortTool;
import java.net.ServerSocket;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class PortRangeParserTests {
  private final PortRangeParser parser = new PortRangeParser();

  @Test
  void expandsRangesAndRemovesDuplicatesInInputOrder() {
    assertThat(parser.parse("80, 443, 8000-8003,8001"))
        .containsExactlyElementsOf(List.of(80, 443, 8000, 8001, 8002, 8003));
    assertThat(parser.canonicalize("80,80,81-82", 3)).isEqualTo("80,81,82");
    assertThat(parser.canonicalizeCompact("443,80-82,81", 4)).isEqualTo("80-82,443");
    assertThat(parser.canonicalizeCompact("1-65535", 65535)).isEqualTo("1-65535");
  }

  @Test
  void rejectsInvalidPortsRangesAndOversizedSelections() {
    assertThatThrownBy(() -> parser.parse("0,80")).isInstanceOf(ApiException.class);
    assertThatThrownBy(() -> parser.parse("65536")).isInstanceOf(ApiException.class);
    assertThatThrownBy(() -> parser.parse("90-80")).isInstanceOf(ApiException.class);
    assertThatThrownBy(() -> parser.parse("80,,443")).isInstanceOf(ApiException.class);
    assertThatThrownBy(() -> parser.parse("8000-8010", 10))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("10");
  }

  @Test
  void tcpScanStillRejectsPortsOutsideAuthorizedRange() {
    TargetPolicyService policy = new TargetPolicyService(false, parser);
    TcpPortTool tool = new TcpPortTool(policy, parser, 1, 20);
    AuthorizedTarget target = new AuthorizedTarget();
    target.setEnabled(true);
    target.setTargetValue("127.0.0.1");
    target.setAllowedPorts("8000-8010");

    assertThatThrownBy(() -> tool.execute(target, Map.of("ports", "8005,9000")))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("授权");
  }

  @Test
  void tcpScanDoesNotExpandAnAuthorizedFullRangeIntoIndividualConnections() {
    TargetPolicyService policy = new TargetPolicyService(false, parser);
    TcpPortTool tool = new TcpPortTool(policy, parser, 1, 20);
    AuthorizedTarget target = new AuthorizedTarget();
    target.setEnabled(true);
    target.setTargetValue("127.0.0.1");
    target.setAllowedPorts("1-65535");

    assertThatThrownBy(() -> tool.execute(target, Map.of("ports", "1-65535")))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("20");
  }

  @Test
  void openPortIsAssetObservationRatherThanVulnerabilityFinding() throws Exception {
    try (ServerSocket server = new ServerSocket(0)) {
      int port = server.getLocalPort();
      TargetPolicyService policy = new TargetPolicyService(false, parser);
      TcpPortTool tool = new TcpPortTool(policy, parser, 1, 20);
      AuthorizedTarget target = new AuthorizedTarget();
      target.setEnabled(true);
      target.setTargetValue("127.0.0.1");
      target.setAllowedPorts(String.valueOf(port));

      var result = tool.execute(target, Map.of("ports", String.valueOf(port)));

      assertThat(result.findings()).isEmpty();
      assertThat(result.data())
          .containsEntry("assessmentType", "ASSET_OBSERVATION")
          .containsEntry("vulnerability", false);
      assertThat(result.summary()).contains("不自动判定为漏洞");
    }
  }
}
