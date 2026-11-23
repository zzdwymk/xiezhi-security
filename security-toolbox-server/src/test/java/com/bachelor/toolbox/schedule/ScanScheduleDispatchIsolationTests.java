package com.bachelor.toolbox.schedule;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.project.AssessmentProjectService;
import com.bachelor.toolbox.project.ProjectAuthorizationService;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.TargetService;
import com.bachelor.toolbox.task.SecurityTask;
import com.bachelor.toolbox.task.TaskService;
import com.bachelor.toolbox.tool.SecurityToolRegistry;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.Callable;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

/**
 * 第364轮：单个坏计划不得中断整批派发。
 *
 * <p>R363 修复后 {@code calculateNextRun} 对语义上永不触发的 cron 抛 {@link ApiException}；
 * 若该异常发生在 {@code dispatchSchedule} 的 catch 分支（推进 nextRunAt 时），会沿调用链冲出
 * {@code dispatchUnderGate} 的循环，导致同一批剩余计划全部不派发，且每 5 秒重复失败。
 * 修复后单计划失败只影响自身，批内后续计划照常派发。
 */
class ScanScheduleDispatchIsolationTests {

  private final ScanScheduleRepository repository = mock(ScanScheduleRepository.class);
  private final TaskService tasks = mock(TaskService.class);
  private final TargetService targets = mock(TargetService.class);
  private final AssessmentProjectService projects = mock(AssessmentProjectService.class);
  private final ProjectAuthorizationService authorization = mock(ProjectAuthorizationService.class);
  private final SecurityToolRegistry toolRegistry = mock(SecurityToolRegistry.class);
  private final com.bachelor.toolbox.tool.ScannerPocSelectionService scannerPocs =
      mock(com.bachelor.toolbox.tool.ScannerPocSelectionService.class);
  private ScanScheduleService service;

  @BeforeEach
  void setUp() throws Exception {
    service =
        new ScanScheduleService(
            repository,
            tasks,
            targets,
            projects,
            authorization,
            new ObjectMapper(),
            toolRegistry,
            scannerPocs);
    when(authorization.isAdmin()).thenReturn(true);
    when(authorization.callWithSystemAccess(any()))
        .thenAnswer(invocation -> ((Callable<?>) invocation.getArgument(0)).call());
    when(targets.getCurrentlyAuthorized(7L)).thenReturn(new AuthorizedTarget());
    when(repository.save(any(ScanSchedule.class)))
        .thenAnswer(invocation -> invocation.getArgument(0));
    when(toolRegistry.require("http_headers"))
        .thenReturn(mock(com.bachelor.toolbox.tool.SecurityTool.class));
  }

  private static ScanSchedule cronSchedule(Long id, String cron) {
    ScanSchedule schedule = new ScanSchedule();
    schedule.setId(id);
    schedule.setProjectId(5L);
    schedule.setTargetId(7L);
    schedule.setToolCode("http_headers");
    schedule.setParametersJson("{}");
    schedule.setCronExpression(cron);
    schedule.setEnabled(true);
    schedule.setNextRunAt(Instant.now().minusSeconds(1));
    return schedule;
  }

  private static ScanSchedule intervalSchedule(Long id) {
    ScanSchedule schedule = new ScanSchedule();
    schedule.setId(id);
    schedule.setProjectId(5L);
    schedule.setTargetId(7L);
    schedule.setToolCode("http_headers");
    schedule.setParametersJson("{}");
    schedule.setIntervalSeconds(3600L);
    schedule.setEnabled(true);
    schedule.setNextRunAt(Instant.now().minusSeconds(1));
    return schedule;
  }

  @Test
  void brokenCronScheduleDoesNotBlockRemainingDispatches() throws Exception {
    ScanSchedule broken = cronSchedule(1L, "0 0 0 31 2 *");
    ScanSchedule healthy = intervalSchedule(2L);
    when(repository.findByEnabledTrueAndNextRunAtLessThanEqual(any(Instant.class), any()))
        .thenReturn(List.of(broken, healthy));
    SecurityTask created = new SecurityTask();
    created.setId(99L);
    when(tasks.create(any(com.bachelor.toolbox.task.CreateTaskRequest.class))).thenReturn(created);

    // 修复前：第一个计划的 advanceSchedule 在 catch 分支再次抛 ApiException，冲出循环 → 本断言失败
    assertDoesNotThrow(() -> service.dispatch());

    // 健康计划的派发不受影响：任务已创建、nextRunAt 已推进
    ArgumentCaptor<com.bachelor.toolbox.task.CreateTaskRequest> captor =
        ArgumentCaptor.forClass(com.bachelor.toolbox.task.CreateTaskRequest.class);
    verify(tasks, times(2)).create(captor.capture());
    assertEquals(2, captor.getAllValues().size());
    assertEquals(7L, captor.getAllValues().get(0).targetId());
    assertEquals(7L, captor.getAllValues().get(1).targetId());
    assertEquals(99L, healthy.getLastTaskId());
    verify(repository, times(1)).save(any(ScanSchedule.class));
    org.assertj.core.api.Assertions.assertThat(healthy.getNextRunAt()).isNotNull();
    // 坏计划：错误已记录（下次轮询重试，但不再阻断批内其它计划）
    org.assertj.core.api.Assertions.assertThat(broken.getLastError())
        .contains("该 Cron 表达式不会再触发任何时间点");
  }
}