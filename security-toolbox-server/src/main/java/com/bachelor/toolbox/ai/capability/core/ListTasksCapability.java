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
 * {@code list_tasks} —— 列出平台内的安全任务（设计文档 §4.2 路线 A）。
 *
 * <p>封装 {@code GET /api/tasks}（{@link TaskService#list}）。
 *
 * <h2>目标绑定：{@link BindingMode#NONE}</h2>
 *
 * <p>只读枚举任务记录，不向任何目标发起动作。任务记录里<strong>含有</strong> {@code targetId} 字段，但"读过一条描述某个目标的
 * 记录"与"触及该目标"是两回事：前者是平台内部数据检索，后者才会产生外部影响。
 *
 * <p>这个区分必须写清楚，否则会走向另一个极端——把所有"提到目标"的读操作都当成"触及目标"并要求 {@code targetId}，
 * 结果是把护栏变成可用性障碍（Agent 连"有哪些任务"都问不了），进而诱发绕过护栏的动机。
 *
 * <p>可选参数 {@code projectId} / {@code targetId} 是<strong>过滤条件</strong>，不改变绑定模式：
 * "有时校验、有时不校验"的开关本身就是漏洞。
 */
@Component
public class ListTasksCapability extends AbstractCoreCapability {

  /** 能力码。 */
  public static final String CODE = "list_tasks";

  private final TaskService tasks;

  public ListTasksCapability(TaskService tasks) {
    super(
        CODE,
        "列出安全任务",
        "列出平台内可见项目的安全任务（含状态、进度、所属项目与目标、工具代码）。"
            + "可选参数 projectId、targetId 仅作为过滤条件。"
            + "只读查询，不向任何授权目标发起动作。",
        CapabilityKind.READ,
        RiskLevel.SAFE,
        false,
        BindingMode.NONE,
        AiCapabilityLayer.L1);
    this.tasks = tasks;
  }

  @Override
  public Map<String, Object> parameterSchema() {
    Map<String, Object> properties = new LinkedHashMap<>();
    properties.put("projectId", integerProperty(1, "可选：只返回该项目下的任务"));
    properties.put("targetId", integerProperty(1, "可选：只返回该目标相关的任务（过滤条件，不是授权校验依据）"));
    return objectSchema(properties, List.of());
  }

  /** 列出任务（可选按项目/目标过滤）。 */
  public List<SecurityTask> list(Long projectId, Long targetId) {
    return tasks.list().stream()
        .filter(task -> projectId == null || projectId.equals(task.getProjectId()))
        .filter(task -> targetId == null || targetId.equals(task.getTargetId()))
        .toList();
  }
}
