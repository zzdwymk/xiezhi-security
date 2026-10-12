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
 * {@code retry_task} —— 重试一个已失败/超时/被拒/已取消的安全任务（设计文档 §4.2 路线 A）。
 *
 * <p>封装 {@code POST /api/tasks/{id}/retry}（{@link TaskService#retry}）。
 *
 * <h2>目标绑定：{@link BindingMode#RESOLVED}（同 {@code cancel_task} 的理由）</h2>
 *
 * <p>重试<strong>就是重新对授权目标发起执行</strong>——它比取消更直接地"触及目标"。若只因为参数里是 {@code taskId} 就声明
 * 不触及目标，护栏会跳过 L-A，Agent 可以对任意目标反复重试扫描。因此 {@code targetId} 同样是必填参数。
 *
 * <p>{@code requiresApproval = true}：重试等于重新执行一次对目标的探测（§6.6 的 {@code REQUIRED} 档）。
 * {@code idempotencyKey} 透传给 {@link TaskService#retry(Long, String)}，用于防止 Agent 重放导致同一任务被重复创建。
 */
@Component
public class RetryTaskCapability extends AbstractCoreCapability {

  /** 能力码。 */
  public static final String CODE = "retry_task";

  private final TaskService tasks;

  public RetryTaskCapability(TaskService tasks) {
    super(
        CODE,
        "重试安全任务",
        "重试一个处于 FAILED / TIMEOUT / REJECTED / CANCELLED 状态的安全任务。"
            + "参数：taskId（要重试的任务）、targetId（该任务扫描的授权目标 ID，必填）、"
            + "idempotencyKey（可选幂等键，防止重复重试）。"
            + "重试会对授权目标重新发起实际执行，因此需要人工确认。",
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
    properties.put("taskId", integerProperty(1, "要重试的任务记录 ID"));
    properties.put("targetId", integerProperty(1, "该任务扫描的授权目标 ID；重试会重新触及该目标"));
    properties.put("idempotencyKey", property("string", "可选幂等键，防止同一任务被重复重试"));
    return objectSchema(properties, List.of("taskId", "targetId"));
  }

  @Override
  protected void validateCoreParams(Map<String, Object> params) {
    requirePositiveLong(params, "taskId");
    requirePositiveLong(params, "targetId");
  }

  /** 重试任务。 */
  public SecurityTask retry(Long taskId, String idempotencyKey) {
    return tasks.retry(taskId, idempotencyKey);
  }
}
