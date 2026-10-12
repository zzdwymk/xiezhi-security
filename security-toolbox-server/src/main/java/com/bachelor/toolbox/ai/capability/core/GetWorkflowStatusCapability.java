package com.bachelor.toolbox.ai.capability.core;

import com.bachelor.toolbox.ai.capability.CapabilityKind;
import com.bachelor.toolbox.ai.capability.RiskLevel;
import com.bachelor.toolbox.task.WorkflowRunDtos;
import com.bachelor.toolbox.task.WorkflowRunService;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Component;

/**
 * {@code get_workflow_status} —— 查询工作流运行的进度与状态（设计文档 §4.2 路线 A）。
 *
 * <p>封装 {@code GET /api/workflow-runs/{id}}（{@link WorkflowRunService#get}）。
 *
 * <h2>目标绑定：{@link BindingMode#NONE}，但理由必须是"确实不触及"</h2>
 *
 * <p>按运行 ID 查询一条已经存在的运行记录及其任务列表，读操作、无副作用，且<strong>不向任何目标发起任何动作</strong>。
 * 这正是三态语义里唯一合法的"空集"情形。
 *
 * <p>注意它<strong>不是</strong>"解析不出目标所以返回空集"——{@code runId} 与 {@code targetId} 是两个不同的东西：
 * 前者是平台内部的运行记录主键，后者是授权目标。把 {@code runId} 当目标解析是概念错误；而"解析不出就返回空集"则是
 * fail-open 缺陷。本能力的空集来自 {@link BindingMode#NONE} 的<strong>显式声明</strong>，护栏的
 * {@code TargetBindingProbe} 会读到该声明才允许跳过 L-A。
 *
 * <p>该能力同时保留 {@code targetId} 为<strong>可选</strong>参数：当调用方想确认"这次运行是不是打在某个目标上"时可以传，
 * 它会作为附加过滤条件，但<strong>不</strong>改变绑定模式——可选参数不能成为"有时校验、有时不校验"的开关。
 */
@Component
public class GetWorkflowStatusCapability extends AbstractCoreCapability {

  /** 能力码。 */
  public static final String CODE = "get_workflow_status";

  private final WorkflowRunService workflowRuns;

  public GetWorkflowStatusCapability(WorkflowRunService workflowRuns) {
    super(
        CODE,
        "查询工作流状态",
        "按运行 ID 查询一次工作流运行的进度、状态、消息与各节点任务列表。"
            + "参数：runId（工作流运行记录 ID）。"
            + "这是只读查询，不向任何授权目标发起动作，因此不需要授权目标参数。",
        CapabilityKind.READ,
        RiskLevel.SAFE,
        false,
        BindingMode.NONE,
        AiCapabilityLayer.L1);
    this.workflowRuns = workflowRuns;
  }

  @Override
  public Map<String, Object> parameterSchema() {
    Map<String, Object> properties = new LinkedHashMap<>();
    properties.put("runId", integerProperty(1, "工作流运行记录 ID（不是授权目标 ID）"));
    return objectSchema(properties, List.of("runId"));
  }

  @Override
  protected void validateCoreParams(Map<String, Object> params) {
    requirePositiveLong(params, "runId");
  }

  /** 查询运行详情。 */
  public WorkflowRunDtos.Detail get(Long runId) {
    return workflowRuns.get(runId);
  }
}
