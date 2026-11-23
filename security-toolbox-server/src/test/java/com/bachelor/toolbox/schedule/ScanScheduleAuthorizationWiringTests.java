package com.bachelor.toolbox.schedule;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import com.bachelor.toolbox.project.AssessmentProjectService;
import com.bachelor.toolbox.project.ProjectAuthorizationService;
import com.bachelor.toolbox.target.TargetService;
import com.bachelor.toolbox.task.TaskService;
import com.bachelor.toolbox.tool.SecurityToolRegistry;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

/**
 * 第366轮：计划接口的归属校验接线守卫。
 *
 * <p>普通用户隔离依赖以下调用存在：{@code get→requireAccess}、{@code toggle/delete→requireManage}、
 * {@code create→validateProjectTarget}（其内部 {@code get→requireAccess}）。此处断言接线，防止后续
 * 重构悄悄移除校验（R342 的 list 隔离已有测试，本文件覆盖其余四个入口）。
 */
class ScanScheduleAuthorizationWiringTests {

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
  void setUp() {
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
    Mockito.when(authorization.isAdmin()).thenReturn(true);
    Mockito.when(targets.getCurrentlyAuthorized(7L))
        .thenReturn(new com.bachelor.toolbox.target.AuthorizedTarget());
    Mockito.when(repository.save(any(ScanSchedule.class)))
        .thenAnswer(invocation -> invocation.getArgument(0));
    Mockito.when(repository.findById(9L))
        .thenReturn(java.util.Optional.of(scheduleWithProject(5L)));
  }

  private static ScanSchedule scheduleWithProject(Long projectId) {
    ScanSchedule schedule = new ScanSchedule();
    schedule.setId(9L);
    schedule.setProjectId(projectId);
    schedule.setTargetId(7L);
    schedule.setToolCode("http_headers");
    schedule.setParametersJson("{}");
    schedule.setIntervalSeconds(3600L);
    schedule.setEnabled(false);
    return schedule;
  }

  @Test
  void getWiresProjectAccessCheck() {
    service.get(9L);
    verify(authorization).requireAccess(5L);
  }

  @Test
  void enableWiresManageCheck() {
    service.toggle(9L, true);
    verify(authorization).requireManage(5L);
  }

  @Test
  void disableWiresManageCheck() {
    service.toggle(9L, false);
    verify(authorization).requireManage(5L);
  }

  @Test
  void deleteWiresManageCheck() {
    service.delete(9L);
    verify(authorization).requireManage(5L);
  }

  @Test
  void createWiresProjectTargetAndTargetAuthorizationChecks() {
    com.bachelor.toolbox.target.AuthorizedTarget target =
        new com.bachelor.toolbox.target.AuthorizedTarget();
    target.setId(7L);
    target.setTargetValue("http://192.168.222.157/");
    target.setEnabled(true);
    Mockito.when(targets.getCurrentlyAuthorized(7L)).thenReturn(target);

    service.create(
        new CreateScheduleRequest(
            5L, 7L, "http_headers", Map.of(), null, 3600L, true));

    // create 的项目归属校验经由 validateProjectTarget → requireAccess 链
    verify(projects).validateProjectTarget(5L, 7L);
    verify(targets).getCurrentlyAuthorized(7L);
    assertThatRepositorySavedWithProject(5L);
  }

  private void assertThatRepositorySavedWithProject(Long projectId) {
    org.mockito.ArgumentCaptor<ScanSchedule> captor =
        org.mockito.ArgumentCaptor.forClass(ScanSchedule.class);
    Mockito.verify(repository).save(captor.capture());
    assertThat(captor.getValue().getProjectId()).isEqualTo(projectId);
  }
}
