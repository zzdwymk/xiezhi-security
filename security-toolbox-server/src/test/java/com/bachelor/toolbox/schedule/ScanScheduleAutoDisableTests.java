package com.bachelor.toolbox.schedule;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.notification.NotificationService;
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
import org.springframework.test.util.ReflectionTestUtils;

/**
 * 第365轮：派发连续失败达到阈值后必须自动停用计划。
 *
 * <p>存量库中的坏计划（如永不触发的 cron）每 5 秒轮询都会派发失败：任务已创建但推进 nextRunAt
 * 抛异常（R364 已保证不阻断批内），但计划会**永远重试**——每次轮询一次 ERROR 日志与一次无效任务创建，
 * 永不收敛。达到连续失败阈值（默认 5）后应自动停用并发布停用通知。
 */
class ScanScheduleAutoDisableTests {

  private final ScanScheduleRepository repository = mock(ScanScheduleRepository.class);
  private final TaskService tasks = mock(TaskService.class);
  private final TargetService targets = mock(TargetService.class);
  private final AssessmentProjectService projects = mock(AssessmentProjectService.class);
  private final ProjectAuthorizationService authorization = mock(ProjectAuthorizationService.class);
  private final SecurityToolRegistry toolRegistry = mock(SecurityToolRegistry.class);
  private final com.bachelor.toolbox.tool.ScannerPocSelectionService scannerPocs =
      mock(com.bachelor.toolbox.tool.ScannerPocSelectionService.class);
  private final NotificationService notifications = mock(NotificationService.class);
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
    service.setNotifications(notifications);
    ReflectionTestUtils.setField(service, "maxConsecutiveFailures", 5);
    when(authorization.isAdmin()).thenReturn(true);
    when(authorization.callWithSystemAccess(any()))
        .thenAnswer(invocation -> ((Callable<?>) invocation.getArgument(0)).call());
    when(targets.getCurrentlyAuthorized(7L)).thenReturn(new AuthorizedTarget());
    when(repository.save(any(ScanSchedule.class)))
        .thenAnswer(invocation -> invocation.getArgument(0));
    when(toolRegistry.require("http_headers"))
        .thenReturn(mock(com.bachelor.toolbox.tool.SecurityTool.class));
    SecurityTask created = new SecurityTask();
    created.setId(99L);
    when(tasks.create(any(com.bachelor.toolbox.task.CreateTaskRequest.class))).thenReturn(created);
  }

  private static ScanSchedule brokenCronSchedule() {
    ScanSchedule schedule = new ScanSchedule();
    schedule.setId(1L);
    schedule.setProjectId(5L);
    schedule.setTargetId(7L);
    schedule.setToolCode("http_headers");
    schedule.setParametersJson("{}");
    schedule.setCronExpression("0 0 0 31 2 *");
    schedule.setEnabled(true);
    schedule.setNextRunAt(Instant.now().minusSeconds(1));
    return schedule;
  }

  @Test
  void repeatedDispatchFailuresAutoDisableSchedule() {
    ScanSchedule broken = brokenCronSchedule();
    when(repository.findByEnabledTrueAndNextRunAtLessThanEqual(any(Instant.class), any()))
        .thenReturn(List.of(broken));

    for (int round = 0; round < 5; round++) {
      service.dispatch();
    }

    // 前四轮推进失败不落库；第 5 轮达到阈值，停用落库
    ArgumentCaptor<ScanSchedule> saved = ArgumentCaptor.forClass(ScanSchedule.class);
    verify(repository, times(1)).save(saved.capture());
    ScanSchedule last = saved.getValue();
    org.assertj.core.api.Assertions.assertThat(last.isEnabled())
        .as("连续 5 次派发失败后计划必须自动停用（此前永远重试）")
        .isFalse();
    org.assertj.core.api.Assertions.assertThat(last.getNextRunAt()).isNull();
    org.assertj.core.api.Assertions.assertThat(last.getConsecutiveFailures()).isEqualTo(5);
    verify(notifications)
        .publish(
            org.mockito.ArgumentMatchers.contains("schedule:1:disabled:"),
            eq(5L),
            eq(false),
            eq("schedule"),
            eq("warning"),
            any(),
            any(),
            any(),
            any());
  }
}
