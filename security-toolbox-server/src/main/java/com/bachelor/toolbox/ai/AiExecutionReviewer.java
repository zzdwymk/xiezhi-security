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
      return new AiAgentResponse.AgentReview("NO_ACTION", "本轮没有执行工具，无需复核", false, List.of());
    }
    List<Long> verified = new ArrayList<>();
    boolean retryAllowed = false;
    for (Long taskId : taskIds) {
      SecurityTask task = taskId == null ? null : tasks.findById(taskId).orElse(null);
      if (task == null
          || !Objects.equals(projectId, task.getProjectId())
          || !Objects.equals(targetId, task.getTargetId())) {
        return new AiAgentResponse.AgentReview(
            "REJECTED", "执行结果无法通过项目与目标归属复核", false, List.copyOf(verified));
      }
      verified.add(taskId);
      retryAllowed |= RETRYABLE.contains(task.getStatus());
    }
    return new AiAgentResponse.AgentReview(
        "ACCEPTED",
        "已复核 " + verified.size() + " 个受控任务，均属于当前项目和授权目标",
        retryAllowed,
        List.copyOf(verified));
  }
}
