package com.bachelor.toolbox.ai.capability.discovery;

import com.bachelor.toolbox.ai.capability.AgentCapability;
import com.bachelor.toolbox.ai.capability.CapabilityKind;
import com.bachelor.toolbox.ai.capability.CapabilityRegistry;
import com.bachelor.toolbox.ai.capability.RiskLevel;
import com.bachelor.toolbox.ai.capability.core.AbstractCoreCapability;
import com.bachelor.toolbox.ai.capability.core.AiCapabilityLayer;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Component;

/**
 * {@code search_capabilities} —— 按关键词搜索 L2 扩展能力（设计文档 §5）。
 *
 * <p>这是"按需解锁"的第一步：Agent 先用它发现能力，再用 {@code unlock_capability} 解锁，之后该能力的完整 schema
 * 才会进入后续轮次的 prompt。
 *
 * <h2>目标绑定：{@link BindingMode#UNRESOLVED} —— 恒返回哨兵</h2>
 *
 * <p>本能力<strong>不执行任何动作</strong>，只查询注册表。直觉上它"显然不触及目标"，但三态语义要求更严格的论证：
 *
 * <ul>
 *   <li>它的输入是<strong>任意关键词</strong>。关键词既可能命中一个只读能力，也可能命中一个扫描能力；
 *   <li>它的输出是"有哪些能力可用"，本身不产生副作用。
 * </ul>
 *
 * <p>那为什么不用空集？因为三态里的空集有<strong>精确含义</strong>："该能力确实不触及任何授权目标，护栏可以跳过 L-A"。
 * 对搜索来说这个结论虽然成立，但这里选择哨兵的真正理由是<strong>保守优先</strong>与<strong>审计价值</strong>：
 *
 * <ol>
 *   <li>返回哨兵会让护栏拒绝该调用，Agent 必须经人工确认才能搜索能力清单——这保证了"能力发现"这一行为本身留痕；
 *   <li>更重要的是<strong>一致性</strong>：{@code bash_probe}、{@code unlock_capability} 同样返回哨兵。若搜索返回空集而解锁
 *       返回哨兵，就会形成一个"先搜索（放行）再解锁（拒绝）"的怪异序列，让人误以为搜索是免费的安全操作。
 * </ol>
 *
 * <p><strong>但必须如实记录一条局限</strong>：把搜索做成需要人工确认，在实践中可能过于保守——它是纯读操作，拒绝它
 * 并不增加任何安全性，只会让 Agent 无法自我发现能力。这是一个<strong>可用性与一致性的取舍</strong>，而非安全必需。
 * 之所以仍选择哨兵，是因为本任务的设计原则是"不确定即 fail-closed"（§10），而"这个能力的参数结构任意、
 * 无法静态证明不触及目标"正是"不确定"。若后续实测确认该确认过于频繁，应通过<strong>显式的策略调整</strong>
 * （把它改成 {@code NONE} 并在设计中记录理由）来解决，而不是悄悄改返回值。
 */
@Component
public class SearchCapabilitiesCapability extends AbstractCoreCapability {

  /** 能力码。 */
  public static final String CODE = "search_capabilities";

  private final CapabilityRegistry registry;

  public SearchCapabilitiesCapability(CapabilityRegistry registry) {
    super(
        CODE,
        "搜索扩展能力",
        "按关键词搜索平台的可解锁扩展能力（L2 层），返回能力码、名称、类别、风险等级与简介。"
            + "参数：keyword（关键词，可匹配能力码、中文名或描述）、limit（可选，返回条数上限，默认 10，最大 "
            + CapabilityLayers.MAX_SEARCH_RESULTS
            + "）。搜索只读不执行；找到后用 unlock_capability 解锁，解锁后该能力的完整参数 schema 才会进入上下文。"
            + "由于关键词可能命中任何能力、参数结构无法静态判定是否触及授权目标，本能力按 fail-closed 处理。",
        CapabilityKind.READ,
        RiskLevel.SAFE,
        false,
        BindingMode.UNRESOLVED,
        AiCapabilityLayer.L1);
    this.registry = registry;
  }

  @Override
  public Map<String, Object> parameterSchema() {
    Map<String, Object> properties = new LinkedHashMap<>();
    properties.put("keyword", property("string", "搜索关键词，如 'fingerprint'、'指纹'、'scan'"));
    properties.put(
        "limit",
        integerProperty(1, "返回条数上限，默认 10，最大 " + CapabilityLayers.MAX_SEARCH_RESULTS));
    return objectSchema(properties, List.of("keyword"));
  }

  @Override
  protected void validateCoreParams(Map<String, Object> params) {
    requireText(params, "keyword");
  }

  /**
   * 执行搜索。
   *
   * <p>只搜索<strong>可解锁</strong>（L2）的能力：L1 已经在 prompt 里，重复返回是浪费上下文；
   * {@code invoke_endpoint} 这类原语同样常驻。
   */
  public List<Map<String, Object>> search(String keyword, Integer limit) {
    int bounded = limit == null ? 10 : limit;
    List<AgentCapability> candidates = new ArrayList<>();
    for (AgentCapability capability : registry.all()) {
      if (CapabilityLayers.isUnlockable(capability)) {
        candidates.add(capability);
      }
    }
    return CapabilityLayers.search(candidates, keyword, bounded).stream()
        .map(CapabilityLayers::summarize)
        .toList();
  }
}
