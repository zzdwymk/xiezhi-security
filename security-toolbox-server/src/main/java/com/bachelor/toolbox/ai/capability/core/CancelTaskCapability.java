package com.bachelor.toolbox.ai.capability.core;

import com.bachelor.toolbox.ai.capability.CapabilityKind;
import com.bachelor.toolbox.ai.capability.RiskLevel;
import com.bachelor.toolbox.task.SecurityTask;
import com.bachelor.toolbox.task.TaskService;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Component;

/**
 * {@code cancel_task} —— 取消一个正在执行或排队中的安全任务（设计文档 §4.2 路线 A）。
 *
 * <h2>目标绑定：{@link BindingMode#RESOLVED}（即使参数里只有 taskId）</h2>
 *
 * <p>这是本包中语义最微妙的一条，值得写清楚：
 *
 * <ul>
 *   <li>从参数看，本能力只接受 {@code taskId}，没有 {@code targetId}；
 *   <li>但它<strong>确实触及授权目标</strong>——它中断的是"对某个授权目标正在进行的扫描"，会改变该目标的执行状态。
 * </ul>
 *
 * <p>若因为"参数里没有 targetId"就声明 {@link BindingMode#NONE}，就等于宣称"取消扫描不触及目标"，护栏会跳过 L-A。
 * 后果是 Agent 可以取消<strong>任意</strong>目标上的扫描——包括用户正在依赖的关键检测，且无需任何授权校验。
 * 这正是 §4.1.1 记录的 fail-open 缺陷的另一种形态：不是"解析失败折叠成空集"，而是"解析依据选错了字段"。
 *
 * <p>因此本能力把 {@code targetId} 列为<strong>必填参数</strong>，并要求调用方显式声明"我要取消的是这个目标上的任务"。
 * 平台侧会由执行层核对 {@code taskId} 与 {@code targetId} 的一致性（{@code TaskService#cancel} 内部按任务自身的目标
 * 执行取消）。这里多要一个参数不是冗余，而是把"本次调用触及哪个目标"从<strong>隐式推断</strong>变成<strong>显式声明</strong>——
 * 护栏无法读数据库反查，只能依赖能力自己的声明。
 *
 * <p>{@code requiresApproval = true}：中断正在进行的检测会让安全评估结果不完整（部分结果、未覆盖的检查项），属于
 * §6.6 中"影响面大且不可自动恢复"的动作。
 */
@Component
public class CancelTaskCapability extends AbstractCoreCapability {

  /** 能力码。 */
  public static final String CODE = "cancel_task";

  private final TaskService tasks;

  public CancelTaskCapability(TaskService tasks) {
    super(
        CODE,
        "取消安全任务",
        "取消一个排队中或执行中的安全任务。参数：taskId（要取消的任务）、"
            + "targetId（该任务正在扫描的授权目标 ID，必填）。"
            + "取消会中断对该目标的检测，可能产生不完整的评估结果，因此需要人工确认；"
            + "targetId 必须与任务实际目标一致，护栏会对其执行授权校验。",
        CapabilityKind.WRITE,
        RiskLevel.SENSITIVE,
        true,
        BindingMode.RESOLVED,
        AiCapabilityLayer.L1);
    this.tasks = tasks;
  }

  @Override
  public Map<String, Object> parameterSchema() {
    Map<String, Object> properties = new LinkedHashMap<>();
    properties.put("taskId", integerProperty(1, "要取消的任务记录 ID"));
    properties.put(
        "targetId",
        integerProperty(1, "该任务正在扫描的授权目标 ID；取消动作触及该目标，护栏据此做授权校验"));
    return objectSchema(properties, List.of("taskId", "targetId"));
  }

  @Override
  protected void validateCoreParams(Map<String, Object> params) {
    requirePositiveLong(params, "taskId");
    requirePositiveLong(params, "targetId");
  }

  /** 取消任务。 */
  public SecurityTask cancel(Long taskId) {
    return tasks.cancel(taskId);
  }
}
