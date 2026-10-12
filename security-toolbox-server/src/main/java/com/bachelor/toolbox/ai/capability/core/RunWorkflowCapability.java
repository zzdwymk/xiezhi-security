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
 * {@code run_workflow} —— 启动一次工作流运行（设计文档 §4.2 路线 A）。
 *
 * <p>封装 {@code POST /api/workflow-runs}（{@link WorkflowRunService#start}）。
 *
 * <h2>这是"间接执行"能力的教科书例子（§6.2）</h2>
 *
 * <p>它的 {@link CapabilityKind} 是 {@link CapabilityKind#WRITE}——因为从 HTTP 语义看它只是"创建一条运行记录"。
 * 但它创建出来的运行会<strong>立刻为每个节点创建安全任务并开始扫描授权目标</strong>。若护栏按 {@code kind} 判定授权，
 * 这条路径就会跳过 L-A：Agent 可以对任意 {@code targetId} 启动工作流，只要它存在于库里。
 *
 * <p>因此本能力按 {@link BindingMode#RESOLVED} 声明目标：{@code targetId} 是必填参数，护栏会对它逐个执行范围、端口、
 * 有效期校验。这正是"授权校验的依据必须是'是否触及目标'，而不是 {@code kind}"这条修正案的落地。
 *
 * <p>另外，{@code requiresApproval = true}：工作流运行会对授权目标发起实际执行，属于 §6.6 的 {@code REQUIRED} 档。
 * 这与 {@code WorkflowRunService#start} 自身对 {@code requiresApproval} 节点要求显式批准的既有语义一致——两层确认
 * 不是冗余：前者是"Agent 这一层要不要惊动人"，后者是"工作流定义里标记的高危节点有没有被批准"。
 */
@Component
public class RunWorkflowCapability extends AbstractCoreCapability {

  /** 能力码。 */
  public static final String CODE = "run_workflow";

  private final WorkflowRunService workflowRuns;

  public RunWorkflowCapability(WorkflowRunService workflowRuns) {
    super(
        CODE,
        "运行工作流",
        "启动一次工作流运行：按项目已保存的工作流规格为每个节点创建安全任务并开始对授权目标执行扫描。"
            + "参数：projectId、targetId（本次执行触及的授权目标，护栏据此做授权校验）、"
            + "workflowId/workflowRevision/workflowDigest（可选，指定要冻结的规格版本；省略则取最新修订）、"
            + "approvedNodeIds（已获人工批准的高危节点）、skippedNodeIds（预检标记为不可用而跳过的节点）。"
            + "本能力会实际触及授权目标，需要人工确认；目标必须已授权且在有效期内，否则护栏拒绝。",
        CapabilityKind.WRITE,
        RiskLevel.SENSITIVE,
        true,
        BindingMode.RESOLVED,
        AiCapabilityLayer.L1);
    this.workflowRuns = workflowRuns;
  }

  @Override
  public Map<String, Object> parameterSchema() {
    Map<String, Object> properties = new LinkedHashMap<>();
    properties.put("projectId", integerProperty(1, "项目 ID"));
    properties.put("targetId", integerProperty(1, "本次运行会扫描的授权目标 ID，用于护栏 L-A 授权校验"));
    properties.put("workflowId", property("string", "要运行的工作流规格 ID；省略则取项目最新修订"));
    properties.put("workflowRevision", integerProperty(1, "工作流规格修订号；省略则取最新"));
    properties.put("workflowDigest", property("string", "工作流规格摘要 sha256:<64 位十六进制>；省略则取最新"));
    properties.put("approvedNodeIds", property("array", "已获人工批准的高危节点 ID 列表"));
    properties.put("skippedNodeIds", property("array", "预检判定不可用、本次跳过的节点 ID 列表"));
    return objectSchema(properties, List.of("projectId", "targetId"));
  }

  /** 启动运行。 */
  public WorkflowRunDtos.Detail start(
      Long projectId,
      Long targetId,
      String workflowId,
      Long workflowRevision,
      String workflowDigest,
      List<String> approvedNodeIds,
      List<String> skippedNodeIds)
      throws Exception {
    return workflowRuns.start(
        new WorkflowRunDtos.StartRequest(
            projectId,
            targetId,
            workflowId,
            workflowRevision,
            workflowDigest,
            approvedNodeIds,
            skippedNodeIds));
  }
}
