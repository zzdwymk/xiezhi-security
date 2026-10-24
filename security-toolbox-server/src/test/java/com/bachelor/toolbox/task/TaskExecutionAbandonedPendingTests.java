package com.bachelor.toolbox.task;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.finding.FindingRepository;
import com.bachelor.toolbox.project.AssessmentProjectService;
import com.bachelor.toolbox.project.ProjectAuthorizationService;
import com.bachelor.toolbox.target.TargetService;
import com.bachelor.toolbox.tool.SecurityToolRegistry;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * 长期停留在 PENDING 的任务必须被回收。
 *
 * <p>实测中三个任务在进程退出后一直停在 PENDING（startedAt/queueStartedAt 均为 null、
 * 日志为空），挂了三天仍在占用并发槽位，并让 pendingTasks 计数永不归零。回收器原来只扫
 * RUNNING，完全不覆盖这种情况。
 */
class TaskExecutionAbandonedPendingTests {
  private final SecurityTaskRepository taskRepository = mock(SecurityTaskRepository.class);
  private final FindingRepository findingRepository = mock(FindingRepository.class);
  private final TargetService targetService = mock(TargetService.class);
  private final AssessmentProjectService projectService = mock(AssessmentProjectService.class);
  private final SecurityToolRegistry registry = mock(SecurityToolRegistry.class);
  private final AuditService auditService = mock(AuditService.class);
  private final TaskSnapshotService snapshotService = mock(TaskSnapshotService.class);
  private final TaskProgressEventService progressEvents = mock(TaskProgressEventService.class);
  private final ProjectAuthorizationService authorization = mock(ProjectAuthorizationService.class);
  private final TaskExecutionControlService executionControl = new TaskExecutionControlService(1, 1);

  private TaskExecutionService service;

  @BeforeEach
  void setUp() {
    when(taskRepository.save(any(SecurityTask.class))).thenAnswer(inv -> inv.getArgument(0));
    service =
        new TaskExecutionService(
            taskRepository,
            findingRepository,
            targetService,
            projectService,
            registry,
            auditService,
            new ObjectMapper(),
            snapshotService,
            executionControl,
            progressEvents,
            authorization);
  }

  private SecurityTask pending(long id, Instant createdAt) {
    SecurityTask task = new SecurityTask();
    task.setId(id);
    task.setToolCode("nmap_service_scan");
    task.setStatus("PENDING");
    task.setCreatedAt(createdAt);
    task.setProgressMessage("等待本地执行资源");
    return task;
  }

  @Test
  void abandonedPendingTaskIsCancelled() {
    Instant longAgo = Instant.now().minus(3, ChronoUnit.DAYS);
    SecurityTask stuck = pending(41L, longAgo);
    when(taskRepository.findAllByStatusOrderByCreatedAtAsc("PENDING")).thenReturn(List.of(stuck));

    service.reapAbandonedPendingTasks(Instant.now());

    assertThat(stuck.getStatus()).isEqualTo("CANCELLED");
    assertThat(stuck.getTerminationReason()).isEqualTo("ABANDONED_PENDING");
    assertThat(stuck.getErrorMessage()).contains("排队状态");
    assertThat(stuck.getFinishedAt()).isNotNull();
    assertThat(stuck.getExecutionLog()).contains("长期处于排队状态");
  }

  @Test
  void recentlyQueuedTaskIsLeftAlone() {
    // 刚入队的任务可能只是在等并发槽位，不能误杀
    SecurityTask fresh = pending(50L, Instant.now().minusSeconds(30));
    when(taskRepository.findAllByStatusOrderByCreatedAtAsc("PENDING")).thenReturn(List.of(fresh));

    service.reapAbandonedPendingTasks(Instant.now());

    assertThat(fresh.getStatus()).isEqualTo("PENDING");
    verify(taskRepository, never()).save(any(SecurityTask.class));
  }

  @Test
  void taskWithLiveWorkerIsNotReaped() {
    Instant longAgo = Instant.now().minus(3, ChronoUnit.DAYS);
    SecurityTask live = pending(60L, longAgo);
    executionControl.registerWorker(60L, Thread.currentThread());
    try {
      when(taskRepository.findAllByStatusOrderByCreatedAtAsc("PENDING")).thenReturn(List.of(live));

      service.reapAbandonedPendingTasks(Instant.now());

      assertThat(live.getStatus()).isEqualTo("PENDING");
    } finally {
      executionControl.clear(60L);
    }
  }

  @Test
  void queuedAtIsPreferedOverCreatedAt() {
    // 任务创建很久但后来才真正入队排队，应从入队时间算起，不按创建时间误杀
    SecurityTask queuedLate = pending(70L, Instant.now().minus(3, ChronoUnit.DAYS));
    queuedLate.setQueueStartedAt(Instant.now().minusSeconds(10));
    when(taskRepository.findAllByStatusOrderByCreatedAtAsc("PENDING")).thenReturn(List.of(queuedLate));

    service.reapAbandonedPendingTasks(Instant.now());

    assertThat(queuedLate.getStatus()).isEqualTo("PENDING");
  }

  @Test
  void scheduledSweepAlsoReapsPending() {
    // 定时清扫（原方法）必须把 PENDING 一并处理，否则僵尸永远不会被清理
    Instant longAgo = Instant.now().minus(3, ChronoUnit.DAYS);
    SecurityTask stuck = pending(80L, longAgo);
    when(taskRepository.findAllByStatusOrderByCreatedAtAsc("RUNNING")).thenReturn(List.of());
    when(taskRepository.findAllByStatusOrderByCreatedAtAsc("PENDING")).thenReturn(List.of(stuck));

    service.reapStaleRunningTasks();

    assertThat(stuck.getStatus()).isEqualTo("CANCELLED");
    assertThat(stuck.getTerminationReason()).isEqualTo("ABANDONED_PENDING");
  }
}
