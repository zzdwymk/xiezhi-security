package com.bachelor.toolbox.ai.capability.core;

import com.bachelor.toolbox.ai.capability.CapabilityKind;
import com.bachelor.toolbox.ai.capability.RiskLevel;
import com.bachelor.toolbox.task.TaskControlStatus;
import com.bachelor.toolbox.task.TaskControlStatusService;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Component;

/**
 * {@code get_task_control_status} —— 查询任务执行控制状态（设计文档 §4.2 路线 A）。
 *
 * <p>封装 {@code GET /api/tasks/control/status}（{@link TaskControlStatusService}）。
 *
 * <h2>目标绑定：{@link BindingMode#NONE}</h2>
 *
 * <p>返回的是<strong>平台级的执行开关状态</strong>（是否暂停调度、并发上限、当前在跑任务数等），与任何具体授权目标无关。
 *
 * <h2>为什么这条能力对 Agent 很重要（不是可有可无的装饰）</h2>
 *
 * <p>没有它，Agent 在"创建任务后没有进展"时无法区分三种情况：
 *
 * <ol>
 *   <li>任务排队中（正常）；
 *   <li>平台执行被人工暂停（需要等待或询问用户）；
 *   <li>任务被拒绝（需要修正参数）。
 * </ol>
 *
 * <p>分不清就会导致 Agent 反复重试或误判失败——而"反复重试"恰好是 §6.6 想避免的确认疲劳来源之一。把执行控制状态
 * 暴露给 Agent，是用<strong>可观测性</strong>换取<strong>更少的无效动作</strong>。
 */
@Component
public class GetTaskControlStatusCapability extends AbstractCoreCapability {

  /** 能力码。 */
  public static final String CODE = "get_task_control_status";

  private final TaskControlStatusService controlStatus;

  public GetTaskControlStatusCapability(TaskControlStatusService controlStatus) {
    super(
        CODE,
        "查询任务执行控制状态",
        "查询平台任务调度的全局控制状态：调度是否暂停、暂停原因、并发上限、当前运行中与排队中的任务数。"
            + "无参数。用于判断'任务没有进展'是排队、被暂停还是被拒绝。只读查询，不触及任何授权目标。",
        CapabilityKind.READ,
        RiskLevel.SAFE,
        false,
        BindingMode.NONE,
        AiCapabilityLayer.L1);
    this.controlStatus = controlStatus;
  }

  @Override
  public Map<String, Object> parameterSchema() {
    return objectSchema(new LinkedHashMap<>(), List.of());
  }

  /** 查询控制状态。 */
  public TaskControlStatus status() {
    return controlStatus.snapshot();
  }
}
