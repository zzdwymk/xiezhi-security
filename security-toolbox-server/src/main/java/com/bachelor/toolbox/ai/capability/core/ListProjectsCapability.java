package com.bachelor.toolbox.ai.capability.core;

import com.bachelor.toolbox.ai.capability.CapabilityKind;
import com.bachelor.toolbox.ai.capability.RiskLevel;
import com.bachelor.toolbox.project.AssessmentProject;
import com.bachelor.toolbox.project.AssessmentProjectService;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Component;

/**
 * {@code list_projects} —— 列出评估项目（设计文档 §4.2 路线 A 的入口能力）。
 *
 * <p>封装 {@code GET /api/projects}（{@link AssessmentProjectService#list}）。
 *
 * <h2>目标绑定：{@link BindingMode#NONE}</h2>
 *
 * <p>列出项目元数据（名称、状态、授权声明与有效期、目标数量）。项目<strong>不是</strong>授权目标——授权单位是
 * {@code AuthorizedTarget}，项目只是它们的容器。因此本能力不触及任何授权目标，是合法的真空集。
 *
 * <p>这条能力在 L1 里的价值是<strong>消除 Agent 的猜测</strong>：没有它，Agent 只能靠"记住"或"猜" projectId，
 * 进而触发一连串失败调用。§7 的提示词明确写着"你不需要猜测平台允许什么"——前提是平台真的把"有什么"告诉它。
 * 这类低风险高价值的只读能力正是"能力完备性"最划算的部分。
 */
@Component
public class ListProjectsCapability extends AbstractCoreCapability {

  /** 能力码。 */
  public static final String CODE = "list_projects";

  private final AssessmentProjectService projects;

  public ListProjectsCapability(AssessmentProjectService projects) {
    super(
        CODE,
        "列出评估项目",
        "列出平台的评估项目及其授权声明、授权有效期与状态。"
            + "可选参数 status（按状态过滤，如 DRAFT、ACTIVE、ARCHIVED）。"
            + "只读查询，不向任何授权目标发起动作。注意：项目是授权目标的容器，项目 ID 不能当作授权目标 ID 使用。",
        CapabilityKind.READ,
        RiskLevel.SAFE,
        false,
        BindingMode.NONE,
        AiCapabilityLayer.L1);
    this.projects = projects;
  }

  @Override
  public Map<String, Object> parameterSchema() {
    Map<String, Object> properties = new LinkedHashMap<>();
    properties.put("status", property("string", "可选：按项目状态过滤"));
    return objectSchema(properties, List.of());
  }

  /** 列出项目。 */
  public List<AssessmentProject> list(String status) {
    String filter = status == null ? "" : status.trim().toUpperCase(java.util.Locale.ROOT);
    return projects.list().stream()
        .filter(
            project ->
                filter.isEmpty()
                    || filter.equalsIgnoreCase(String.valueOf(project.getStatus())))
        .toList();
  }
}
