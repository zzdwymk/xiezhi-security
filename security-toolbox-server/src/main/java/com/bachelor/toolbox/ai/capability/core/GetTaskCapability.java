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
 * {@code get_task} —— 查询单个安全任务的详情（设计文档 §4.2 路线 A）。
 *
 * <p>封装 {@code GET /api/tasks/{id}}（{@link TaskService#get}）。
 *
 * <p>目标绑定 {@link BindingMode#NONE}：只读读取一条任务记录，不向目标发起动作。{@code taskId} 是平台内部主键，
 * 不是授权目标 ID——把两者混为一谈会导致"用任意数字当 targetId 骗过授权校验"。
 */
@Component
public class GetTaskCapability extends AbstractCoreCapability {

  /** 能力码。 */
  public static final String CODE = "get_task";

  private final TaskService tasks;

  public GetTaskCapability(TaskService tasks) {
    super(
        CODE,
        "查询任务详情",
        "按任务 ID 查询单个安全任务的完整信息（状态、进度、工具代码、参数、结果摘要、所属项目与目标）。"
            + "参数：taskId（任务记录 ID，不是授权目标 ID）。只读查询，不向任何授权目标发起动作。",
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
    properties.put("taskId", integerProperty(1, "任务记录 ID（不是授权目标 ID）"));
    return objectSchema(properties, List.of("taskId"));
  }

  @Override
  protected void validateCoreParams(Map<String, Object> params) {
    requirePositiveLong(params, "taskId");
  }

  /** 查询任务。 */
  public SecurityTask get(Long taskId) {
    return tasks.get(taskId);
  }
}
