package com.bachelor.toolbox.tool;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.PortRangeParser;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/**
 * 任务创建期的「端口子集」校验（第375轮）。
 *
 * <p>此前 {@code tcp_ports}/{@code nmap_service_scan}/{@code fscan_scan} 的越界端口只在**工具执行期**
 * 被拦下（工具自带授权校验，fail-closed），于是 {@code POST /api/tasks} 先返回 202、任务随后 FAILED，
 * 留下失败任务记录并占用一次任务配额。本类把该校验前移到唯一执行入口，与护栏 L-C' 的
 * {@code validatePortSubset} 语义一致：请求的每个端口都必须落在目标授权端口范围内。
 *
 * <p>授权侧用 {@link PortRangeParser#containsPort} 逐端口判断，不展开 {@code allowedPorts}
 * （避免 {@code 1-65535} 产生 65,535 个 Integer）。
 */
public final class ToolPortScope {

  /** 需要端口子集校验的工具（与 {@code EndpointParameterPolicy.PORT_TOOLS} 同源）。 */
  public static final Set<String> PORT_SCOPED_TOOLS =
      Set.of("tcp_ports", "nmap_service_scan", "fscan_scan");

  private ToolPortScope() {}

  /**
   * 校验请求端口是否都在目标授权范围内。
   *
   * @param parser 端口解析器；为 {@code null} 时跳过（与既有可空装配保持一致）
   * @param maxPorts 单次请求允许解析的端口数上限
   * @throws ApiException 端口格式非法或越出授权范围
   */
  public static void requireWithinAuthorization(
      AuthorizedTarget target,
      String toolCode,
      Map<String, Object> parameters,
      PortRangeParser parser,
      int maxPorts) {
    if (target == null || parser == null || toolCode == null || !PORT_SCOPED_TOOLS.contains(toolCode)) {
      return;
    }
    Object raw = parameters == null ? null : parameters.get("ports");
    if (raw == null || String.valueOf(raw).isBlank()) {
      return; // 未指定端口 → 由执行层回落到授权端口集合，本身不越权
    }
    String requested = String.valueOf(raw).trim();
    Set<Integer> wanted;
    try {
      wanted = parser.parse(requested, Math.max(1, maxPorts));
    } catch (ApiException | IllegalArgumentException invalid) {
      throw new ApiException("端口范围格式无效: " + invalid.getMessage());
    }
    String authorized = target.getAllowedPorts();
    Set<Integer> escaped = new LinkedHashSet<>();
    for (Integer port : wanted) {
      if (!parser.containsPort(authorized, port)) escaped.add(port);
    }
    if (!escaped.isEmpty()) {
      throw new ApiException("请求的端口超出目标授权范围: " + escaped);
    }
  }
}
