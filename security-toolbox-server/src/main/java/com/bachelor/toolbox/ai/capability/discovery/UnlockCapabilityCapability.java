package com.bachelor.toolbox.ai.capability.discovery;

import com.bachelor.toolbox.ai.capability.AgentCapability;
import com.bachelor.toolbox.ai.capability.CapabilityKind;
import com.bachelor.toolbox.ai.capability.CapabilityRegistry;
import com.bachelor.toolbox.ai.capability.RiskLevel;
import com.bachelor.toolbox.ai.capability.core.AbstractCoreCapability;
import com.bachelor.toolbox.ai.capability.core.AiCapabilityLayer;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Component;

/**
 * {@code unlock_capability} —— 解锁一个 L2 扩展能力（设计文档 §5，借鉴 ARTEX 的 {@code DeferredTools}/{@code UnlockSet}）。
 *
 * <h2>目标绑定：{@link BindingMode#UNRESOLVED} —— 恒返回哨兵</h2>
 *
 * <p>与 {@code search_capabilities} 同理，而且这里的理由更硬：本能力的参数是<strong>"要解锁哪个能力"</strong>，
 * 而被解锁的能力<strong>可能是一个扫描能力</strong>。也就是说，本次调用虽然不直接执行扫描，却改变了"后续 Agent
 * 能看到哪些能力"这一状态。把这种"改变可达面"的动作声明为"不触及目标"，是在为后续的越权铺路。
 *
 * <p>因此恒返回哨兵，由护栏 fail-closed。
 *
 * <h2>⚠️ 解锁不是提权（本类最重要的约定）</h2>
 *
 * <p>{@link UnlockedCapabilitySet} 只影响<strong>提示词构建</strong>，不参与任何授权判定：
 *
 * <ul>
 *   <li>解锁了 {@code endpoint_delete_api_tasks_by_id} 并不意味着调用它会通过——护栏照常按该能力自己的
 *       {@code risk}/{@code targetBindings} 判定，该拒绝的还是拒绝；
 *   <li>未解锁的能力被直接调用时，护栏同样照常校验，不会因为"没解锁"而额外拒绝，也不会因为"解锁了"而放行。
 * </ul>
 *
 * <p>这个设计的直接好处是<strong>绕过解锁毫无收益</strong>：Agent 若试图跳过 unlock 直接调用 L2 能力，它面对的是
 * 与解锁后<strong>完全相同</strong>的护栏。于是"解锁机制被绕过"不再是一个安全问题，最多是一个上下文占用问题。
 * 反之，若把解锁接进护栏做成权限门，解锁状态本身就会成为新的攻击面。
 *
 * <h2>为什么解锁对象必须是已注册能力</h2>
 *
 * <p>{@link UnlockedCapabilitySet#unlock} 会先查注册表。这防止解锁集合变成一个<strong>比注册表更宽</strong>的清单——
 * 否则一个拼写错误或恶意构造的能力码会留在解锁集合里，等待将来某个同码能力被注册时"自动获得解锁"，形成一条
 * 时间维度的绕过路径（先埋名字，后种能力）。
 */
@Component
public class UnlockCapabilityCapability extends AbstractCoreCapability {

  /** 能力码。 */
  public static final String CODE = "unlock_capability";

  private final CapabilityRegistry registry;
  private final UnlockedCapabilitySet unlocked;

  public UnlockCapabilityCapability(CapabilityRegistry registry, UnlockedCapabilitySet unlocked) {
    super(
        CODE,
        "解锁扩展能力",
        "解锁一个 L2 扩展能力，使其完整参数 schema 进入后续轮次的上下文。"
            + "参数：code（要解锁的能力码，先用 search_capabilities 找到）、sessionId（可选，会话标识）。"
            + "解锁只是让能力对模型可见，不改变任何授权判定——解锁后的能力仍要经过与 L1 能力完全相同的护栏校验。"
            + "由于被解锁的能力可能是扫描能力、本调用改变了后续可达面，因此按 fail-closed 处理。",
        CapabilityKind.WRITE,
        RiskLevel.SAFE,
        false,
        BindingMode.UNRESOLVED,
        AiCapabilityLayer.L1);
    this.registry = registry;
    this.unlocked = unlocked;
  }

  @Override
  public Map<String, Object> parameterSchema() {
    Map<String, Object> properties = new LinkedHashMap<>();
    properties.put("code", property("string", "要解锁的能力码，须已在注册表中登记"));
    properties.put("sessionId", property("string", "可选：会话标识；省略时落到默认会话桶"));
    return objectSchema(properties, List.of("code"));
  }

  @Override
  protected void validateCoreParams(Map<String, Object> params) {
    requireText(params, "code");
  }

  /**
   * 执行解锁。
   *
   * @return 解锁结果与解锁后能力的简要信息（不含完整 schema，由 prompt 构建层按需取）
   */
  public Map<String, Object> unlock(String code, String sessionId) {
    UnlockedCapabilitySet.UnlockResult result = unlocked.unlock(sessionId, code);
    Map<String, Object> response = new LinkedHashMap<>();
    response.put("accepted", result.accepted());
    response.put("code", result.code());
    response.put("message", result.message());
    response.put("unlockedCodes", List.copyOf(unlocked.unlockedCodes(sessionId)));
    if (result.accepted()) {
      AgentCapability capability = registry.find(result.code()).orElse(null);
      if (capability != null) {
        response.put("capability", CapabilityLayers.summarize(capability));
      }
    }
    return Map.copyOf(response);
  }
}
