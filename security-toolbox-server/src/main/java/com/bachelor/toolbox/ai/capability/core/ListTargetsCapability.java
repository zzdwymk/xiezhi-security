package com.bachelor.toolbox.ai.capability.core;

import com.bachelor.toolbox.ai.capability.CapabilityKind;
import com.bachelor.toolbox.ai.capability.RiskLevel;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.TargetService;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Component;

/**
 * {@code list_targets} —— 列出已授权目标（设计文档 §4.2 路线 A 的入口能力）。
 *
 * <h2>目标绑定：{@link BindingMode#NONE} —— 这是本包最需要谨慎论证的一条</h2>
 *
 * <p>表面上"列出授权目标"像是在"触及目标"，但三态语义判定的不是"能力名字里有没有 target 这个词"，而是
 * <strong>本次调用是否会对某个授权目标产生作用</strong>：
 *
 * <ul>
 *   <li>它读取的是<strong>授权元数据</strong>（目标值、类型、允许端口、授权有效期、启用状态），不是目标上的任何内容；
 *   <li>它不向任何目标发包、不改状态、不创建任务；
 *   <li>返回的结果正是"护栏 L-A 会允许哪些目标"这一事实本身——它不扩大可达面，只是让可达面<strong>可见</strong>。
 * </ul>
 *
 * <p>换个角度更能说明问题：如果把这个能力声明为 {@link BindingMode#RESOLVED}，它会陷入"要查授权目标必须先提供授权目标 ID"
 * 的循环——这是逻辑上的死结，而不是更严格的安全。
 *
 * <p>真正需要防的是"读授权列表 → 顺便扫一遍"的联想越权，而这条路径上的<strong>扫描动作</strong>（{@code create_task}、
 * {@code run_workflow}）都已经各自声明了 {@code RESOLVED}，护栏在那里拦截。安全边界应当落在<strong>产生副作用的动作</strong>上，
 * 而不是落在"读取清单"上。
 *
 * <p>另外，把本能力放进 L1 直接暴露是刻意的：Agent 能自己看到授权边界，才会在越界前停下，而不是靠护栏事后拒绝来
 * 学习边界（§7"明确告知边界是环境属性，Agent 才能专注任务本身"）。
 */
@Component
public class ListTargetsCapability extends AbstractCoreCapability {

  /** 能力码。 */
  public static final String CODE = "list_targets";

  private final TargetService targets;

  public ListTargetsCapability(TargetService targets) {
    super(
        CODE,
        "列出授权目标",
        "列出平台已授权的目标及其授权边界：目标值、类型、允许端口范围、授权有效期、启用状态。"
            + "可选参数 projectId（只列该项目关联的目标）、enabled（只看启用/停用）。"
            + "本能力只读取授权元数据，不向任何目标发包、不改状态。"
            + "请据此判断哪些目标在授权范围内——越界目标上的任何扫描都会被护栏拒绝。",
        CapabilityKind.READ,
        RiskLevel.SAFE,
        false,
        BindingMode.NONE,
        AiCapabilityLayer.L1);
    this.targets = targets;
  }

  @Override
  public Map<String, Object> parameterSchema() {
    Map<String, Object> properties = new LinkedHashMap<>();
    properties.put("projectId", integerProperty(1, "可选：只返回该项目关联的授权目标"));
    properties.put("enabled", property("boolean", "可选：true 只看启用目标，false 只看停用目标"));
    return objectSchema(properties, List.of());
  }

  /** 列出授权目标。 */
  public List<AuthorizedTarget> list(Boolean enabled) {
    return targets.list().stream()
        .filter(target -> enabled == null || enabled == target.isEnabled())
        .toList();
  }
}
