package com.bachelor.toolbox.tool;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * 第379轮：tcp_ports 的端口状态明细必须有界，但分类计数必须完整。
 *
 * <p>授权范围允许 {@code 1-65535}，此前 {@code states} 会把 65,535 条明细整包写进任务结果
 * （持久化到 {@code result_json} 并经详情接口回传）。{@code states} 只用于展示/复核，下游读取的是
 * {@code openPorts}，所以可以只返回样本——但必须同时给出**完整**的分类计数，信息不得丢失。
 */
@DisplayName("端口状态明细有界化（第379轮）")
class PortStateSummaryTests {

  private static Map<Integer, String> states(int closedCount, int openCount) {
    Map<Integer, String> map = new LinkedHashMap<>();
    int port = 1;
    for (int i = 0; i < closedCount; i++) map.put(port++, "CLOSED_OR_FILTERED");
    for (int i = 0; i < openCount; i++) map.put(port++, "OPEN");
    return map;
  }

  @Test
  @DisplayName("明细超过上限时只保留样本，计数仍完整且标记截断")
  void largeStateMapIsSampledButCountsStayComplete() {
    Map<Integer, String> all = states(65_500, 35);
    PortStateSummary.Summary summary = PortStateSummary.summarize(all, 500);

    assertThat(summary.sample()).as("明细必须封顶").hasSize(500);
    assertThat(summary.total()).isEqualTo(65_535);
    assertThat(summary.truncated()).isTrue();
    assertThat(summary.counts())
        .as("分类计数必须完整，不能因截断失真")
        .containsEntry("CLOSED_OR_FILTERED", 65_500)
        .containsEntry("OPEN", 35);
  }

  @Test
  @DisplayName("明细未超上限时不截断，样本与总计一致")
  void smallStateMapIsNotTruncated() {
    PortStateSummary.Summary summary = PortStateSummary.summarize(states(3, 1), 500);
    assertThat(summary.sample()).hasSize(4);
    assertThat(summary.total()).isEqualTo(4);
    assertThat(summary.truncated()).isFalse();
    assertThat(summary.counts()).containsEntry("OPEN", 1).containsEntry("CLOSED_OR_FILTERED", 3);
  }

  @Test
  @DisplayName("样本保持原始端口顺序（结果可复现）")
  void sampleKeepsIterationOrder() {
    PortStateSummary.Summary summary = PortStateSummary.summarize(states(5, 0), 3);
    assertThat(summary.sample().keySet()).containsExactly(1, 2, 3);
  }

  @Test
  @DisplayName("空映射与非法上限被安全处理")
  void degenerateInputsAreSafe() {
    PortStateSummary.Summary empty = PortStateSummary.summarize(Map.of(), 500);
    assertThat(empty.total()).isZero();
    assertThat(empty.truncated()).isFalse();
    assertThat(empty.counts()).isEmpty();
    assertThat(PortStateSummary.summarize(null, 500).total()).isZero();
    // 上限非法时按 1 处理，不抛异常（由调用方常量保证，此处防御）
    assertThat(PortStateSummary.summarize(states(3, 0), 0).sample()).hasSize(1);
  }
}
