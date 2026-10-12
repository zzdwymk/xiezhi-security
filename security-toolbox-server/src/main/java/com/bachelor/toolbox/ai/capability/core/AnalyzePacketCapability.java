package com.bachelor.toolbox.ai.capability.core;

import com.bachelor.toolbox.ai.capability.CapabilityKind;
import com.bachelor.toolbox.ai.capability.RiskLevel;
import com.bachelor.toolbox.traffic.TrafficAnalysisService;
import com.bachelor.toolbox.traffic.TrafficPacket;
import com.bachelor.toolbox.traffic.TrafficPacketRepository;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Component;

/**
 * {@code analyze_packet} —— 对一条已捕获报文做 AI 安全分析（设计文档 §4.2 路线 A）。
 *
 * <h2>目标绑定：{@link BindingMode#RESOLVED}</h2>
 *
 * <p>分析本身调用的是平台内的 AI 模型，<strong>不向目标发包</strong>。但它<strong>确实触及授权目标</strong>，理由有二：
 *
 * <ol>
 *   <li>分析结果会写入该报文的风险等级（{@code packet.setRiskLevel}）与 AI 状态，直接影响"这个目标被判定为什么风险"；
 *   <li>{@link TrafficAnalysisService#execute} 这类后续动作会把建议<strong>直接变成对目标执行的安全任务</strong>——分析是这条
 *       链路的入口，把它当成"不触及目标"的纯读操作，等于给间接执行留了一个不受授权校验的入口。
 * </ol>
 *
 * <p>因此本能力要求 {@code targetId} 必填。这不是形式主义：护栏 L-A 无法读数据库反查"这条报文属于哪个目标"，只能采信
 * 能力的显式声明。
 *
 * <p>等级 {@link RiskLevel#SENSITIVE}，不要求逐次确认：分析不产生外部副作用（不发包），§6.6 中归 {@code BATCH} 档，
 * 强制逐次确认反而会制造确认疲劳。
 */
@Component
public class AnalyzePacketCapability extends AbstractCoreCapability {

  /** 能力码。 */
  public static final String CODE = "analyze_packet";

  private final TrafficAnalysisService analysis;
  private final TrafficPacketRepository packets;

  public AnalyzePacketCapability(TrafficAnalysisService analysis, TrafficPacketRepository packets) {
    super(
        CODE,
        "分析流量报文",
        "对一条已捕获的 HTTP 报文做安全分析，产出风险等级、结论与后续验证建议。"
            + "参数：packetId（报文 ID）、targetId（该报文所属的授权目标 ID，必填）、"
            + "mode（可选分析模式，默认 standard）。"
            + "分析结果会更新该报文的风险等级，并可能成为后续对目标发起检测的依据，因此需要目标授权校验。"
            + "本能力不向目标发包；执行建议请用 run_workflow 或 create_task。",
        CapabilityKind.READ,
        RiskLevel.SENSITIVE,
        false,
        BindingMode.RESOLVED,
        AiCapabilityLayer.L1);
    this.analysis = analysis;
    this.packets = packets;
  }

  @Override
  public Map<String, Object> parameterSchema() {
    Map<String, Object> properties = new LinkedHashMap<>();
    properties.put("packetId", integerProperty(1, "要分析的流量报文 ID"));
    properties.put("targetId", integerProperty(1, "该报文所属的授权目标 ID，用于护栏 L-A 授权校验"));
    properties.put("mode", property("string", "可选：分析模式，默认 standard"));
    return objectSchema(properties, List.of("packetId", "targetId"));
  }

  @Override
  protected void validateCoreParams(Map<String, Object> params) {
    requirePositiveLong(params, "packetId");
    requirePositiveLong(params, "targetId");
  }

  /** 执行分析。 */
  public TrafficAnalysisService.AnalysisResponse analyze(Long packetId, String mode) {
    return analysis.analyze(packetId, mode == null ? "standard" : mode);
  }

  /** 报文元数据，供调用方核对目标归属。 */
  public TrafficPacket packet(Long packetId) {
    return packets.findById(packetId).orElse(null);
  }
}
