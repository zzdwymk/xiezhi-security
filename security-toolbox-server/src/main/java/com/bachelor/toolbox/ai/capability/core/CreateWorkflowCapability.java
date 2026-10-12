package com.bachelor.toolbox.ai.capability.core;

import com.bachelor.toolbox.ai.AgentWorkflowSpecService;
import com.bachelor.toolbox.ai.capability.CapabilityKind;
import com.bachelor.toolbox.ai.capability.RiskLevel;
import com.bachelor.toolbox.common.ApiException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Component;

/**
 * {@code create_workflow} —— 创建/覆盖项目的工作流规格（设计文档 §4.2 路线 A）。
 *
 * <p>封装 {@code PUT /api/ai/workflow}（{@link AgentWorkflowSpecService#save}）。工作流是"一组会扫描目标的步骤"的
 * <strong>定义</strong>，本身不执行；但它定义了后续 {@code run_workflow} 会打哪些目标。
 *
 * <h2>为什么 {@code targetBindings} 必须解析真实目标</h2>
 *
 * <p>工作流规格绑定到 {@code projectId}（{@code scopeId}），而项目授权范围由 {@code AssessmentProjectService} 维护。
 * 本能力按 {@code RESOLVED} 模式声明：参数里的 {@code targetId} 会被解析出来交给护栏 L-A 逐个校验。
 *
 * <p>这里刻意<strong>不</strong>因为"创建动作本身不触网"就返回空集：一个工作流规格可以被后续执行用于任意目标，若创建阶段
 * 跳过授权校验，Agent 就能在未授权目标上预先铺好扫描管线（§6.2 的"间接执行"正是这一类）。
 */
@Component
public class CreateWorkflowCapability extends AbstractCoreCapability {

  /** 能力码。 */
  public static final String CODE = "create_workflow";

  private final AgentWorkflowSpecService workflowSpecs;

  public CreateWorkflowCapability(AgentWorkflowSpecService workflowSpecs) {
    super(
        CODE,
        "创建工作流",
        "为指定项目创建或覆盖工作流规格（一组有序的安全工具步骤）。"
            + "参数：projectId（项目 ID，同时作为工作流作用域）、spec（工作流文档对象，V2 图结构或 legacy steps）、"
            + "targetId（本次编排会触及的授权目标，用于护栏授权校验）。"
            + "本能力只保存定义、不执行扫描；执行请用 run_workflow。"
            + "保存的步骤若会在后续执行时扫描目标，必须显式声明 targetId，否则护栏按 fail-closed 拒绝。",
        CapabilityKind.WRITE,
        RiskLevel.SENSITIVE,
        false,
        BindingMode.RESOLVED,
        AiCapabilityLayer.L1);
    this.workflowSpecs = workflowSpecs;
  }

  @Override
  public Map<String, Object> parameterSchema() {
    Map<String, Object> properties = new LinkedHashMap<>();
    properties.put("projectId", integerProperty(1, "项目 ID，工作流规格的作用域"));
    properties.put("targetId", integerProperty(1, "本次编排会触及的授权目标 ID，用于护栏 L-A 授权校验"));
    properties.put("spec", property("object", "工作流文档：V2 图结构（nodes/edges）或 legacy steps 数组"));
    return objectSchema(properties, List.of("projectId", "spec", "targetId"));
  }

  @Override
  protected void validateCoreParams(Map<String, Object> params) {
    requirePositiveLong(params, "projectId");
    Map<String, Object> spec = optionalMap(params, "spec");
    if (spec.isEmpty()) {
      throw new ApiException("工作流规格不能为空");
    }
  }

  /** 保存工作流规格。 */
  public Map<String, Object> save(Long projectId, Map<String, Object> spec) {
    return workflowSpecs.save(projectId, spec);
  }
}
