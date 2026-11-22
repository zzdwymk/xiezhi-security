package com.bachelor.toolbox.tool;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import com.bachelor.toolbox.target.TargetPolicyService;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import org.junit.jupiter.api.Test;

/**
 * 第332轮：afrog 结果中的 matches 列表必须有上限。
 *
 * <p>findings 已受 MAX_FINDINGS（500）限制，但 matches 仍然无界：一次返回大量结果时（JSON 上限
 * 16MB 内可容纳几十万条小对象），matches 会全部保留在响应与内存里，形成响应体积/内存放大。
 */
class AfrogOutputParserTests {

  private static AfrogScanTool tool() {
    return new AfrogScanTool(
        mock(TargetPolicyService.class), new ObjectMapper(), null, "afrog", 60);
  }

  private static String resultsJson(int count) {
    String items =
        IntStream.range(0, count)
            .mapToObj(
                i ->
                    "{\"isvul\":true,\"fulltarget\":\"http://192.168.222.157/\","
                        + "\"pocinfo\":{\"id\":\"poc-1\",\"infoname\":\"测试\",\"infoseg\":\"high\"}}")
            .collect(Collectors.joining(","));
    return "[" + items + "]";
  }

  @Test
  void matchesAreCappedLikeFindings() {
    ScannerPocSelectionService.SelectedPoc selected =
        new ScannerPocSelectionService.SelectedPoc(
            "CVE-2024-0001", "poc-1", "测试", "high", Path.of("poc.yml"), "sha");
    var result =
        tool().parseOutput(URI.create("http://192.168.222.157/"), List.of(selected), resultsJson(600));

    assertThat(result.findings()).hasSize(500);
    @SuppressWarnings("unchecked")
    List<Object> matches = (List<Object>) result.data().get("matches");
    assertThat(matches)
        .as("matches 必须有上限，当前 %s 条", matches.size())
        .hasSizeLessThanOrEqualTo(500);
    // Round 333：截断必须是可见的——总数不能等于截断后的条数，且要有 truncated 标记。
    assertThat(result.data().get("matchCount"))
        .as("matchCount 必须反映真实匹配总数（600），不能等于截断后的 500")
        .isEqualTo(600);
    assertThat(result.data().get("truncated")).isEqualTo(true);
  }
}
