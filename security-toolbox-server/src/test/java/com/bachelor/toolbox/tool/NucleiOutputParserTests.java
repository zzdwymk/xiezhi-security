package com.bachelor.toolbox.tool;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.target.PortRangeParser;
import com.bachelor.toolbox.target.TargetPolicyService;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import org.junit.jupiter.api.Test;

/**
 * 第331轮：nuclei 输出解析的健壮性。
 *
 * <p>覆盖：畸形/非 JSON 行被忽略、授权范围外的 matched-at 必须 fail-closed、匹配数超过上限时
 * 截断并标记 truncated、空输出返回 0。
 */
class NucleiOutputParserTests {

  private static NucleiScanTool tool() {
    return new NucleiScanTool(
        mock(TargetPolicyService.class),
        new PortRangeParser(),
        new ObjectMapper(),
        "nuclei",
        System.getProperty("java.io.tmpdir"),
        65535,
        60);
  }

  private static String matchLine(String templateId, String matchedAt) {
    return "{\"template-id\":\""
        + templateId
        + "\",\"info\":{\"name\":\""
        + templateId
        + "\",\"severity\":\"high\"},\"matched-at\":\""
        + matchedAt
        + "\"}";
  }

  @Test
  void malformedLinesAreIgnored() {
    String output =
        String.join(
            "\n",
            "not json at all",
            "{broken json",
            matchLine("CVE-2024-0001", "http://192.168.222.157/"),
            "{\"no-template\":true}");
    var result = tool().parseOutput("192.168.222.157", "80", output);
    assertThat(result.data().get("matchCount")).isEqualTo(1);
    assertThat(result.findings()).hasSize(1);
  }

  @Test
  void outOfScopeMatchFailsClosed() {
    String output = matchLine("CVE-2024-0002", "http://evil.example.com/");
    assertThatThrownBy(() -> tool().parseOutput("192.168.222.157", "80", output))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("授权范围外");
  }

  @Test
  void matchesAreTruncatedAtLimit() {
    String output =
        IntStream.range(0, 600)
            .mapToObj(i -> matchLine("CVE-2024-" + i, "http://192.168.222.157/"))
            .collect(Collectors.joining("\n"));
    var result = tool().parseOutput("192.168.222.157", "80", output);
    assertThat(result.data().get("matchCount")).isEqualTo(600);
    assertThat(result.data().get("truncated")).isEqualTo(true);
    assertThat(result.findings()).hasSize(500);
  }

  @Test
  void blankOutputYieldsZero() {
    var result = tool().parseOutput("192.168.222.157", "80", "");
    assertThat(result.data().get("matchCount")).isEqualTo(0);
    assertThat(result.findings()).isEmpty();
  }
}
