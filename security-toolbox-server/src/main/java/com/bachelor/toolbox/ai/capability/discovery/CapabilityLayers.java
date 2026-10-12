package com.bachelor.toolbox.ai.capability.discovery;

import com.bachelor.toolbox.ai.capability.AgentCapability;
import com.bachelor.toolbox.ai.capability.CapabilityKind;
import com.bachelor.toolbox.ai.capability.RiskLevel;
import com.bachelor.toolbox.ai.capability.core.AbstractCoreCapability;
import com.bachelor.toolbox.ai.capability.core.AiCapabilityLayer;
import com.bachelor.toolbox.ai.endpoint.EndpointCapability;
import com.bachelor.toolbox.ai.endpoint.InvokeEndpointCapability;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;

/**
 * L2 扩展层的判定与分类（设计文档 §5 分层暴露策略）。
 *
 * <h2>为什么需要这个类，而不是"给能力加个字段就行"</h2>
 *
 * <p>L2 的成员来自<strong>两个互不认识的来源</strong>：
 *
 * <ol>
 *   <li>本包手工标注的 L2 能力（实现 {@link AbstractCoreCapability#layer()}）；
 *   <li>端点自动派生能力（{@link EndpointCapability}，§4.2 路线 B）——它们由 MVC 映射表生成，<strong>不可能</strong>
 *       预先知道自己是 L1 还是 L2，因为 L1 是"人工挑选的核心域"这一产品决策。
 * </ol>
 *
 * <p>因此分层判定必须在<strong>运行期</strong>由一个统一的策略给出，而不是散落在各能力里。否则会出现"端点能力
 * 全都既不在 L1 也不在 L2"的第三种状态，让 {@code search_capabilities} 漏掉它们——那正是本方案要避免的"能力静默不可达"。
 *
 * <h2>L1 的判定依据是"是否已直接进 prompt"，不是"是否重要"</h2>
 *
 * <p>手工标注为 {@link AiCapabilityLayer#L1} 的能力直接进 prompt；{@code invoke_endpoint} 原语也直接暴露（它是
 * 路线 C 的兜底，必须常驻）。其余<strong>全部</strong>归 L2，由 {@code search_capabilities} 按需发现。这个规则是
 * <strong>全序且无遗漏</strong>的：任何能力必然属于 L1 或 L2 之一，不存在"查不到也调不到"的第三态。
 *
 * <h2>L2 不是权限等级</h2>
 *
 * <p>把能力放进 L2 只意味着"它的 schema 不默认占用上下文"。解锁后它与 L1 能力走<strong>完全相同</strong>的
 * {@code CapabilityGate}（L-B/L-C/L-A/L-D）。这一点必须反复强调：如果 L2 被误解成"需要提权才能用"，就会有人把
 * 高危能力"降级"到 L2 来规避审查，而实际上分层与风险完全正交。
 */
public final class CapabilityLayers {

  /** 搜索时可返回的最大结果数，防止一次搜索把 L2 全量灌进上下文。 */
  public static final int MAX_SEARCH_RESULTS = 30;

  private CapabilityLayers() {}

  /**
   * 判定一个能力的分层。
   *
   * <p>顺序：手工标注优先 → {@code invoke_endpoint} 原语 → 其余归 L2。
   */
  public static AiCapabilityLayer layerOf(AgentCapability capability) {
    if (capability == null) {
      return AiCapabilityLayer.L2;
    }
    if (capability instanceof AbstractCoreCapability core) {
      return core.layer();
    }
    if (InvokeEndpointCapability.CODE.equals(capability.code())) {
      // 路线 C 的兜底原语必须常驻 prompt：它的存在本身就是"能力完备"的保证。
      return AiCapabilityLayer.L1;
    }
    // 端点派生能力（路线 B）与其它的动态来源：一律 L2，按需解锁。
    return AiCapabilityLayer.L2;
  }

  /** 是否为 L1（直接暴露，无需解锁）。 */
  public static boolean isDirectlyExposed(AgentCapability capability) {
    return layerOf(capability).isDirectlyExposed();
  }

  /** 是否为可解锁的 L2 能力。 */
  public static boolean isUnlockable(AgentCapability capability) {
    return layerOf(capability) == AiCapabilityLayer.L2;
  }

  /**
   * 按关键词搜索能力。
   *
   * <p>匹配范围：能力码、中文名、描述。匹配策略是<strong>大小写不敏感的子串匹配</strong>，并按相关度排序
   * （能力码精确匹配 &gt; 码前缀 &gt; 码包含 &gt; 名称包含 &gt; 描述包含）。
   *
   * <p>刻意<strong>不</strong>引入模糊匹配或语义检索：本方法的输出会直接决定 Agent 解锁哪些能力，一个"猜出来的"
   * 结果会让 Agent 基于错误前提规划。宁可返回空并让 Agent 换个关键词，也不要返回貌似相关的结果。
   *
   * @param capabilities 待搜索的能力集合
   * @param keyword 关键词；空白时返回空列表（不做"列全部"）
   * @param limit 结果上限，受 {@link #MAX_SEARCH_RESULTS} 约束
   */
  public static java.util.List<AgentCapability> search(
      Iterable<AgentCapability> capabilities, String keyword, int limit) {
    if (keyword == null || keyword.isBlank()) {
      return java.util.List.of();
    }
    String needle = keyword.trim().toLowerCase(Locale.ROOT);
    int bounded = Math.min(Math.max(limit, 1), MAX_SEARCH_RESULTS);
    java.util.List<Scored> hits = new java.util.ArrayList<>();
    for (AgentCapability capability : capabilities) {
      int score = scoreOf(capability, needle);
      if (score > 0) {
        hits.add(new Scored(capability, score));
      }
    }
    hits.sort(
        java.util.Comparator.comparingInt(Scored::score)
            .reversed()
            .thenComparing(scored -> scored.capability().code()));
    return hits.stream().limit(bounded).map(Scored::capability).toList();
  }

  /** 相关度打分；0 表示不匹配。 */
  private static int scoreOf(AgentCapability capability, String needle) {
    String code = capability.code() == null ? "" : capability.code().toLowerCase(Locale.ROOT);
    if (code.equals(needle)) {
      return 100;
    }
    if (code.startsWith(needle)) {
      return 80;
    }
    if (code.contains(needle)) {
      return 60;
    }
    String name = capability.displayName() == null ? "" : capability.displayName().toLowerCase(Locale.ROOT);
    if (name.contains(needle)) {
      return 40;
    }
    String description =
        capability.description() == null ? "" : capability.description().toLowerCase(Locale.ROOT);
    if (description.contains(needle)) {
      return 20;
    }
    return 0;
  }

  /** 一个能力的简要视图，用于搜索结果（不返回完整 schema，避免上下文膨胀）。 */
  public static java.util.Map<String, Object> summarize(AgentCapability capability) {
    java.util.Map<String, Object> summary = new java.util.LinkedHashMap<>();
    summary.put("code", capability.code());
    summary.put("name", capability.displayName());
    summary.put("kind", String.valueOf(capability.kind()));
    summary.put("risk", String.valueOf(capability.risk()));
    summary.put("requiresApproval", capability.requiresApproval());
    summary.put("layer", layerOf(capability).name());
    summary.put("unlockable", isUnlockable(capability));
    summary.put("description", capability.description());
    return java.util.Map.copyOf(summary);
  }

  /**
   * 枚举"可解锁"的 L2 能力码前缀。
   *
   * <p>供文档与审计使用：端点派生能力的码格式为 {@code endpoint_<method>_<segments>}
   * （{@link EndpointCapability#CODE_PREFIX}），手工 L2 能力则各有自己的前缀。
   */
  public static Set<String> knownL2Prefixes() {
    Set<String> prefixes = new LinkedHashSet<>();
    prefixes.add(EndpointCapability.CODE_PREFIX);
    return Set.copyOf(prefixes);
  }

  /**
   * 危险等级排序用的数值（仅用于展示排序，<strong>不得</strong>作为授权判定依据）。
   *
   * <p>授权判定只认 {@code AgentCapability#targetBindings}——见 §6.2。这里提供排序值只是为了让搜索结果把高风险能力
   * 排在前面，便于 Agent 与用户注意。
   */
  public static int riskOrdinal(RiskLevel risk) {
    return risk == null ? -1 : risk.ordinal();
  }

  /** 类别排序值（同上，仅展示用）。 */
  public static int kindOrdinal(CapabilityKind kind) {
    return kind == null ? -1 : kind.ordinal();
  }

  private record Scored(AgentCapability capability, int score) {}
}
