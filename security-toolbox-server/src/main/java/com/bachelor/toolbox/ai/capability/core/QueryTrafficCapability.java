package com.bachelor.toolbox.ai.capability.core;

import com.bachelor.toolbox.ai.capability.CapabilityKind;
import com.bachelor.toolbox.ai.capability.RiskLevel;
import com.bachelor.toolbox.traffic.TrafficPacket;
import com.bachelor.toolbox.traffic.TrafficPacketRepository;
import com.bachelor.toolbox.traffic.TrafficProxyService;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.springframework.stereotype.Component;

/**
 * {@code query_traffic} —— 查询已捕获的 HTTP 流量（设计文档 §4.2 路线 A）。
 *
 * <p>封装 {@code GET /api/traffic/sessions} 的查询语义。
 *
 * <h2>目标绑定：{@link BindingMode#NONE}</h2>
 *
 * <p>检索<strong>已经捕获</strong>的报文记录（方法、主机、路径、状态码、风险等级等元数据），只读、不重新发包。
 * 可选参数 {@code targetId} / {@code host} 只是过滤条件。
 *
 * <p>刻意<strong>不</strong>返回报文的 {@code requestBody}/{@code responseBody} 等敏感字段（实体上它们标了
 * {@code @JsonIgnore}）：能力层返回的应当是"索引与元数据"，正文需要时由 {@code analyze_packet} 单独取。这既控制了
 * 上下文体积，也避免把可能含有凭据的正文批量塞进模型。
 */
@Component
public class QueryTrafficCapability extends AbstractCoreCapability {

  /** 能力码。 */
  public static final String CODE = "query_traffic";

  /** 单次返回上限。 */
  private static final int MAX_RESULTS = 200;

  private final TrafficProxyService proxy;
  private final TrafficPacketRepository packets;

  public QueryTrafficCapability(TrafficProxyService proxy, TrafficPacketRepository packets) {
    super(
        CODE,
        "查询流量",
        "查询平台已捕获的 HTTP 流量元数据（方法、scheme、主机、端口、路径、状态码、风险等级、AI 分析状态）。"
            + "参数均为可选过滤条件：targetId、host（主机名关键字）、method（HTTP 方法）、path（路径关键字）、limit。"
            + "只读查询，不重新发包；报文正文需用 analyze_packet 单独分析。",
        CapabilityKind.READ,
        RiskLevel.SAFE,
        false,
        BindingMode.NONE,
        AiCapabilityLayer.L1);
    this.proxy = proxy;
    this.packets = packets;
  }

  @Override
  public Map<String, Object> parameterSchema() {
    Map<String, Object> properties = new LinkedHashMap<>();
    properties.put("targetId", integerProperty(1, "可选：目标 ID 过滤（过滤条件，不是授权校验依据）"));
    properties.put("host", property("string", "可选：主机名关键字"));
    properties.put("method", property("string", "可选：HTTP 方法，如 GET、POST"));
    properties.put("path", property("string", "可选：路径关键字"));
    properties.put("limit", integerProperty(1, "可选：返回条数上限，默认 50，最大 " + MAX_RESULTS));
    return objectSchema(properties, List.of());
  }

  /** 查询流量元数据。 */
  public List<TrafficPacket> list(
      Long targetId, String host, String method, String path, Integer limit) {
    int bounded = Math.min(Math.max(limit == null ? 50 : limit, 1), MAX_RESULTS);
    String hostFilter = host == null ? "" : host.trim().toLowerCase(Locale.ROOT);
    String methodFilter = method == null ? null : method.trim().toUpperCase(Locale.ROOT);
    String pathFilter = path == null ? "" : path.trim();
    return proxy.packets().stream()
        .filter(packet -> targetId == null || targetId.equals(packet.getTargetId()))
        .filter(
            packet ->
                hostFilter.isEmpty()
                    || String.valueOf(packet.getHost()).toLowerCase(Locale.ROOT).contains(hostFilter))
        .filter(
            packet ->
                methodFilter == null
                    || methodFilter.equalsIgnoreCase(String.valueOf(packet.getMethod())))
        .filter(
            packet ->
                pathFilter.isEmpty() || String.valueOf(packet.getPath()).contains(pathFilter))
        .limit(bounded)
        .toList();
  }

  /** 按报文 ID 取元数据（不含正文）。 */
  public TrafficPacket get(Long packetId) {
    return proxy.getPacket(packetId);
  }

  /** 底层仓库，供同包的其它能力复用。 */
  TrafficPacketRepository repository() {
    return packets;
  }
}
