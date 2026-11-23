package com.bachelor.toolbox.tool;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 端口探测结果的有界摘要（第379轮）。
 *
 * <p>{@code tcp_ports} 的 {@code states} 是「每个被探测端口 → 状态」的完整映射。授权范围允许
 * {@code 1-65535}，此时结果里会出现 65,535 条记录并随任务持久化到 {@code result_json}、
 * 经任务详情接口回传，形成无界载荷。
 *
 * <p>{@code states} 只用于展示与复核；下游（{@code consumeOpenPorts}）读取的是 {@code openPorts}，
 * 因此可以安全地只返回样本，同时用 {@link Summary#counts()} 给出**完整**的分类计数——
 * 信息不丢失（"有多少 OPEN/CLOSED"仍可知），只是明细被有界化。
 */
public final class PortStateSummary {

  private PortStateSummary() {}

  /**
   * @param sample 前 {@code limit} 条明细（保持原迭代顺序）
   * @param total 明细总数
   * @param truncated 是否发生截断
   * @param counts 按状态汇总的完整计数
   */
  public record Summary(
      Map<Integer, String> sample, int total, boolean truncated, Map<String, Integer> counts) {}

  public static Summary summarize(Map<Integer, String> states, int limit) {
    if (states == null || states.isEmpty()) {
      return new Summary(Map.of(), 0, false, Map.of());
    }
    int bound = Math.max(1, limit);
    Map<Integer, String> sample = new LinkedHashMap<>();
    Map<String, Integer> counts = new LinkedHashMap<>();
    for (Map.Entry<Integer, String> entry : states.entrySet()) {
      String state = entry.getValue() == null ? "UNKNOWN" : entry.getValue();
      counts.merge(state, 1, Integer::sum);
      if (sample.size() < bound) {
        sample.put(entry.getKey(), entry.getValue());
      }
    }
    return new Summary(sample, states.size(), states.size() > sample.size(), counts);
  }
}
