package com.bachelor.toolbox.ai;

import com.bachelor.toolbox.task.SecurityTask;
import com.bachelor.toolbox.task.SecurityTaskRepository;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import org.springframework.stereotype.Service;

/** Read-only reviewer. It can report retry eligibility but can never create or retry a task. */
@Service
public class AiExecutionReviewer {
  private static final Set<String> RETRYABLE = Set.of("FAILED", "TIMEOUT", "REJECTED", "CANCELLED");
  private final SecurityTaskRepository tasks;

  public AiExecutionReviewer(SecurityTaskRepository tasks) {
    this.tasks = tasks;
  }

  public AiAgentResponse.AgentReview review(Long projectId, Long targetId, List<Long> taskIds) {
    if (taskIds == null || taskIds.isEmpty()) {
      return new AiAgentResponse.AgentReview("NO_ACTION", "本轮没有创建任务，没有可核对的任务状态", false, List.of());
    }
    List<Long> verified = new ArrayList<>();
    boolean retryAllowed = false;
    boolean pending = false;
    for (Long taskId : taskIds) {
      SecurityTask task = taskId == null ? null : tasks.findById(taskId).orElse(null);
      if (task == null
          || !Objects.equals(projectId, task.getProjectId())
          || !Objects.equals(targetId, task.getTargetId())) {
        return new AiAgentResponse.AgentReview(
            "REJECTED", "任务无法通过项目与目标归属核对，未核验检测结果", false, List.copyOf(verified));
      }
      verified.add(taskId);
      retryAllowed |= RETRYABLE.contains(task.getStatus());
      pending |= !"SUCCESS".equals(task.getStatus()) && !RETRYABLE.contains(task.getStatus());
    }
    return new AiAgentResponse.AgentReview(
        pending ? "PENDING" : "ACCEPTED",
        "已核对 " + verified.size() + " 个任务的项目、目标归属和当前状态；"
            + (pending ? "仍有任务尚未结束，等待实际执行结果；" : "任务状态已终结；")
            + "此核对不包含检测证据或结果内容验证",
        retryAllowed,
        List.copyOf(verified));
  }
}
