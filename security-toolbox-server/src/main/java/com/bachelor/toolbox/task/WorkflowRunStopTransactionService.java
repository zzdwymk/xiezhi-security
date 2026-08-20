package com.bachelor.toolbox.task;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.project.AssessmentProjectService;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/** Commits the stop marker before task cancellation so background schedulers see it immediately. */
@Service
public class WorkflowRunStopTransactionService {
  private static final Set<String> RUN_TERMINALS =
      Set.of("COMPLETED", "PARTIAL_FAILED", "FAILED", "STOPPED");
  private static final Set<String> TASK_TERMINALS =
      Set.of("SUCCESS", "FAILED", "TIMEOUT", "REJECTED", "CANCELLED", "SKIPPED");

  private final WorkflowRunRepository runs;
  private final SecurityTaskRepository tasks;
  private final AssessmentProjectService projects;

  public WorkflowRunStopTransactionService(
      WorkflowRunRepository runs,
      SecurityTaskRepository tasks,
      AssessmentProjectService projects) {
    this.runs = runs;
    this.tasks = tasks;
    this.projects = projects;
  }

  @Transactional(propagation = Propagation.REQUIRES_NEW)
  public WorkflowRun begin(Long id) {
    WorkflowRun run = requireRun(id);
    if (RUN_TERMINALS.contains(run.getStatus())) return run;
    run.setStatus("STOPPING");
    run.setMessage("正在取消已创建的工作流任务");
    return runs.saveAndFlush(run);
  }

  @Transactional(propagation = Propagation.REQUIRES_NEW)
  public WorkflowRun finish(Long id) {
    WorkflowRun run = requireRun(id);
    if (RUN_TERMINALS.contains(run.getStatus())) return run;
    List<SecurityTask> runTasks = tasks.findAllByWorkflowRunIdOrderByCreatedAtAsc(id);
    long remaining =
        runTasks.stream().filter(task -> !TASK_TERMINALS.contains(task.getStatus())).count();
    if (remaining > 0) {
      run.setStatus("STOPPING");
      run.setMessage("仍有 " + remaining + " 个任务正在响应停止请求");
      return runs.save(run);
    }
    long cancelled = runTasks.stream().filter(task -> "CANCELLED".equals(task.getStatus())).count();
    run.setStatus("STOPPED");
    run.setProgress(100);
    run.setMessage("工作流已停止，" + cancelled + " 个任务已取消");
    run.setFinishedAt(Instant.now());
    return runs.save(run);
  }

  private WorkflowRun requireRun(Long id) {
    WorkflowRun run =
        runs.findByIdForUpdate(id).orElseThrow(() -> new ApiException("工作流运行记录不存在"));
    projects.get(run.getProjectId());
    if (run.getClearedAt() != null) throw new ApiException("工作流运行记录已清空");
    return run;
  }
}
