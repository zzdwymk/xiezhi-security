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

  /**
   * 第359轮：containsPort 与 parse 的授权语义必须逐点等价。
   *
   * <p>containsPort 不展开范围集合；命中前段后仍要校验后续 token（迟到非法段必须让整段授权失败），
   * 否则 {@code 80,bad} 这类串会退化成「只认前段」的宽松放行。
   */
  @Test
  void containsPortMatchesParseMembershipForValidSpecifications() {
    List<String> specs = List.of("80", "80,443", "80-82", "8000-8010,443", "1-65535", "80, 443 ");
    List<Integer> probes = List.of(1, 80, 81, 82, 443, 65535, 8005, 9000);
    for (String spec : specs) {
      var parsed = parser.parse(spec);
      for (int port : probes) {
        assertThat(parser.containsPort(spec, port))
            .as("containsPort(%s, %d) 必须与 parse().contains() 等价", spec, port)
            .isEqualTo(parsed.contains(port));
      }
    }
  }

  @Test
  void containsPortRejectsLateInvalidTokensInsteadOfTrustingAPrefixMatch() {
    assertThatThrownBy(() -> parser.containsPort("80,bad", 80)).isInstanceOf(ApiException.class);
    assertThatThrownBy(() -> parser.containsPort("bad,80", 80)).isInstanceOf(ApiException.class);
    assertThatThrownBy(() -> parser.containsPort("80,,443", 80)).isInstanceOf(ApiException.class);
    assertThatThrownBy(() -> parser.containsPort("80,,443", 443)).isInstanceOf(ApiException.class);
    assertThatThrownBy(() -> parser.containsPort("80,0", 80)).isInstanceOf(ApiException.class);
    assertThatThrownBy(() -> parser.containsPort("0-65536", 80)).isInstanceOf(ApiException.class);
    assertThatThrownBy(() -> parser.containsPort(null, 80)).isInstanceOf(ApiException.class);
    assertThatThrownBy(() -> parser.containsPort("  ", 80)).isInstanceOf(ApiException.class);
  }

  @Test
  void containsPortCoversFullRangeWithoutExpansionCost() {
    assertThat(parser.containsPort("1-65535", 1)).isTrue();
    assertThat(parser.containsPort("1-65535", 65535)).isTrue();
    assertThat(parser.containsPort("1-65535", 0)).isFalse();
    assertThat(parser.containsPort("1-65535", 65536)).isFalse();
    assertThat(parser.containsPort("80-82", 83)).isFalse();
  }

  @Test
  void parseKeepsDeduplicationAndMaxPortsLimitsForToolSelection() {
    // 去重后 2 个唯一端口，限额 2 内合法（工具选择仍必须走 parse，不能用 containsPort 替代）。
    assertThat(parser.parse("80,80,81", 2)).containsExactly(80, 81);
    // 80-82 展开后 3 个唯一端口，超过限额 2 必须拒绝。
    assertThatThrownBy(() -> parser.parse("80-82", 2)).isInstanceOf(ApiException.class);
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
