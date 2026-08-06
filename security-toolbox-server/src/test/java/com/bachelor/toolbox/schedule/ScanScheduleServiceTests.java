package com.bachelor.toolbox.schedule;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.project.AssessmentProjectService;
import com.bachelor.toolbox.project.ProjectAuthorizationService;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.TargetService;
import com.bachelor.toolbox.task.CreateTaskRequest;
import com.bachelor.toolbox.task.SecurityTask;
import com.bachelor.toolbox.task.TaskService;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.Callable;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;

class ScanScheduleServiceTests {
  private final ScanScheduleRepository repository = mock(ScanScheduleRepository.class);
  private final TaskService tasks = mock(TaskService.class);
  private final TargetService targets = mock(TargetService.class);
  private final AssessmentProjectService projects = mock(AssessmentProjectService.class);
  private final ProjectAuthorizationService authorization = mock(ProjectAuthorizationService.class);
  private ScanScheduleService service;

  @BeforeEach
  void setUp() throws Exception {
    service =
        new ScanScheduleService(
            repository, tasks, targets, projects, authorization, new ObjectMapper());
    when(authorization.isAdmin()).thenReturn(true);
    when(authorization.callWithSystemAccess(any()))
        .thenAnswer(
            invocation -> {
              Callable<?> operation = invocation.getArgument(0);
              return operation.call();
            });
    when(targets.getCurrentlyAuthorized(7L)).thenReturn(new AuthorizedTarget());
    when(repository.save(any(ScanSchedule.class)))
        .thenAnswer(invocation -> invocation.getArgument(0));
  }

  @Test
  void listsSchedulesWithBoundedDeterministicPageable() {
    List<ScanSchedule> schedules = List.of(intervalSchedule(1L), intervalSchedule(2L));
    when(repository.findAll(any(Pageable.class))).thenReturn(new PageImpl<>(schedules));

    assertEquals(schedules, service.list());

    ArgumentCaptor<Pageable> pageableCaptor = ArgumentCaptor.forClass(Pageable.class);
    verify(repository).findAll(pageableCaptor.capture());
    Pageable pageable = pageableCaptor.getValue();
    assertEquals(0, pageable.getPageNumber());
    assertTrue(pageable.getPageSize() <= 1000);
    assertEquals(
        org.springframework.data.domain.Sort.Order.desc("createdAt"),
        pageable.getSort().getOrderFor("createdAt"));
    assertEquals(
        org.springframework.data.domain.Sort.Order.desc("id"),
        pageable.getSort().getOrderFor("id"));
  }

  @Test
  void ordinaryUserListFiltersByProjectOwnerBeforeApplyingTheLimit() {
    ScanSchedule schedule = intervalSchedule(1L);
    when(authorization.isAdmin()).thenReturn(false);
    when(authorization.currentUsername()).thenReturn("alice");
    when(repository.findAccessibleByProjectOwner(
            org.mockito.ArgumentMatchers.eq("alice"), any(Pageable.class)))
        .thenReturn(new PageImpl<>(List.of(schedule)));

    assertEquals(List.of(schedule), service.list());

    ArgumentCaptor<Pageable> pageableCaptor = ArgumentCaptor.forClass(Pageable.class);
    verify(repository)
        .findAccessibleByProjectOwner(
            org.mockito.ArgumentMatchers.eq("alice"), pageableCaptor.capture());
    assertTrue(pageableCaptor.getValue().getPageSize() <= 1000);
    verify(repository, never()).findAll(any(Pageable.class));
  }

  @Test
  void reportsMissingScheduleInChinese() {
    when(repository.findById(404L)).thenReturn(Optional.empty());

    ApiException exception = assertThrows(ApiException.class, () -> service.get(404L));

    assertEquals("扫描计划不存在", exception.getMessage());
  }

  @Test
  void getsScheduleOnlyAfterProjectAccessCheck() {
    ScanSchedule schedule = intervalSchedule(11L);
    when(repository.findById(11L)).thenReturn(Optional.of(schedule));

    assertEquals(schedule, service.get(11L));

    verify(authorization).requireAccess(5L);
  }

  @Test
  void createsProjectScopedScheduleWithNonNullProjectColumn() {
    Instant before = Instant.now();

    ScanSchedule created = service.create(intervalRequest(Map.of("depth", 2), true));

    assertEquals(5L, created.getProjectId());
    assertEquals(7L, created.getTargetId());
    assertEquals("http_headers", created.getToolCode());
    assertEquals("{\"depth\":2}", created.getParametersJson());
    assertNotNull(created.getNextRunAt());
    assertTrue(created.getNextRunAt().isAfter(before.plus(Duration.ofMinutes(59))));
    verify(projects).validateProjectTarget(5L, 7L);
    verify(repository).save(created);
  }

  @Test
  void defaultsMissingParametersAndEnabledFlag() {
    ScanSchedule created = service.create(intervalRequest(null, null));

    assertEquals("{}", created.getParametersJson());
    assertTrue(created.isEnabled());
    assertNotNull(created.getNextRunAt());
  }

  @Test
  void disabledScheduleDoesNotAdvertiseAnImmediateRun() {
    ScanSchedule created = service.create(intervalRequest(Map.of(), false));

    assertFalse(created.isEnabled());
    assertNull(created.getNextRunAt());
  }

  @Test
  void reportsParameterSerializationFailureInChinese() throws Exception {
    ObjectMapper failingMapper = mock(ObjectMapper.class);
    when(failingMapper.writeValueAsString(any()))
        .thenThrow(new JsonProcessingException("serialization failed") {});
    ScanScheduleService failingService =
        new ScanScheduleService(repository, tasks, targets, projects, authorization, failingMapper);

    ApiException exception =
        assertThrows(
            ApiException.class,
            () -> failingService.create(intervalRequest(Map.of("depth", 2), true)));

    assertEquals("扫描参数无效", exception.getMessage());
    verify(repository, never()).save(any());
  }

  @Test
  void enablingScheduleRecalculatesNextRunInsteadOfDispatchingImmediately() {
    ScanSchedule schedule = intervalSchedule(11L);
    schedule.setEnabled(false);
    schedule.setNextRunAt(Instant.now().minusSeconds(120));
    when(repository.findById(11L)).thenReturn(Optional.of(schedule));
    Instant before = Instant.now();

    ScanSchedule enabled = service.toggle(11L, true);

    assertTrue(enabled.isEnabled());
    assertTrue(enabled.getNextRunAt().isAfter(before.plus(Duration.ofMinutes(59))));
    verify(authorization).requireManage(5L);
    verify(repository).save(schedule);
  }

  @Test
  void disablingScheduleClearsNextRun() {
    ScanSchedule schedule = intervalSchedule(11L);
    schedule.setEnabled(true);
    schedule.setNextRunAt(Instant.now().plusSeconds(3600));
    when(repository.findById(11L)).thenReturn(Optional.of(schedule));

    ScanSchedule disabled = service.toggle(11L, false);

    assertFalse(disabled.isEnabled());
    assertNull(disabled.getNextRunAt());
    verify(authorization).requireManage(5L);
    verify(repository).save(schedule);
  }

  @Test
  void deletesExistingSchedule() {
    ScanSchedule schedule = intervalSchedule(11L);
    when(repository.findById(11L)).thenReturn(Optional.of(schedule));

    service.delete(11L);

    verify(authorization).requireManage(5L);
    verify(repository).delete(schedule);
  }

  @Test
  void rejectsTogglingScheduleOutsideManagedProjectBeforeSaving() {
    ScanSchedule schedule = intervalSchedule(11L);
    when(repository.findById(11L)).thenReturn(Optional.of(schedule));
    doThrow(new ApiException("无权访问该评估项目"))
        .when(authorization)
        .requireManage(5L);

    ApiException exception =
        assertThrows(ApiException.class, () -> service.toggle(11L, false));

    assertEquals("无权访问该评估项目", exception.getMessage());
    verify(repository, never()).save(schedule);
  }

  @Test
  void dispatchCreatesTaskAndRecordsSuccessfulRun() throws Exception {
    ScanSchedule schedule = intervalSchedule(11L);
    schedule.setParametersJson("{\"depth\":2}");
    when(repository.findByEnabledTrueAndNextRunAtLessThanEqual(
            any(Instant.class), any(Pageable.class)))
        .thenReturn(List.of(schedule));
    SecurityTask task = new SecurityTask();
    task.setId(91L);
    when(tasks.create(any(CreateTaskRequest.class))).thenReturn(task);
    Instant before = Instant.now();

    service.dispatch();

    Instant after = Instant.now();
    ArgumentCaptor<CreateTaskRequest> requestCaptor =
        ArgumentCaptor.forClass(CreateTaskRequest.class);
    verify(tasks).create(requestCaptor.capture());
    verify(authorization).callWithSystemAccess(any());
    CreateTaskRequest request = requestCaptor.getValue();
    assertEquals(5L, request.projectId());
    assertEquals(7L, request.targetId());
    assertEquals("http_headers", request.toolCode());
    assertEquals(Map.of("depth", 2), request.parameters());
    assertEquals(91L, schedule.getLastTaskId());
    assertNotNull(schedule.getLastRunAt());
    assertFalse(schedule.getLastRunAt().isBefore(before));
    assertFalse(schedule.getLastRunAt().isAfter(after));
    assertEquals(
        Duration.ofSeconds(3600),
        Duration.between(schedule.getLastRunAt(), schedule.getNextRunAt()));
    ArgumentCaptor<Pageable> pageableCaptor = ArgumentCaptor.forClass(Pageable.class);
    verify(repository)
        .findByEnabledTrueAndNextRunAtLessThanEqual(
            any(Instant.class), pageableCaptor.capture());
    Pageable pageable = pageableCaptor.getValue();
    assertTrue(pageable.getPageSize() <= 1000);
    assertEquals(
        org.springframework.data.domain.Sort.Order.asc("nextRunAt"),
        pageable.getSort().getOrderFor("nextRunAt"));
    assertEquals(
        org.springframework.data.domain.Sort.Order.asc("id"),
        pageable.getSort().getOrderFor("id"));
    verify(repository).save(schedule);
  }

  @Test
  void dispatchFailureLeavesRunMetadataUntouchedAndAdvancesSchedule() throws Exception {
    ScanSchedule schedule = intervalSchedule(11L);
    when(repository.findByEnabledTrueAndNextRunAtLessThanEqual(
            any(Instant.class), any(Pageable.class)))
        .thenReturn(List.of(schedule));
    when(tasks.create(any(CreateTaskRequest.class))).thenThrow(new ApiException("任务创建失败"));
    Instant before = Instant.now();

    service.dispatch();

    Instant after = Instant.now();
    assertNull(schedule.getLastRunAt());
    assertNull(schedule.getLastTaskId());
    assertFalse(schedule.getNextRunAt().isBefore(before.plusSeconds(3600)));
    assertFalse(schedule.getNextRunAt().isAfter(after.plusSeconds(3600)));
    verify(repository).save(schedule);
  }

  @Test
  void dispatchContinuesAfterMalformedParameters() throws Exception {
    ScanSchedule malformed = intervalSchedule(11L);
    malformed.setParametersJson("not-json");
    ScanSchedule valid = intervalSchedule(12L);
    when(repository.findByEnabledTrueAndNextRunAtLessThanEqual(
            any(Instant.class), any(Pageable.class)))
        .thenReturn(List.of(malformed, valid));
    SecurityTask task = new SecurityTask();
    task.setId(92L);
    when(tasks.create(any(CreateTaskRequest.class))).thenReturn(task);

    service.dispatch();

    assertNull(malformed.getLastRunAt());
    assertNotNull(malformed.getNextRunAt());
    assertNotNull(valid.getLastRunAt());
    assertEquals(92L, valid.getLastTaskId());
    verify(tasks).create(any(CreateTaskRequest.class));
    verify(repository).save(malformed);
    verify(repository).save(valid);
  }

  @Test
  void rejectsTargetThatDoesNotBelongToProject() {
    doThrow(new ApiException("目标不属于该评估项目")).when(projects).validateProjectTarget(5L, 7L);

    assertThrows(ApiException.class, () -> service.create(intervalRequest(Map.of(), true)));

    verify(targets, never()).getCurrentlyAuthorized(any());
    verify(repository, never()).save(any());
  }

  @Test
  void rejectsMissingProjectBeforePersistenceInsteadOfHittingNotNullConstraint() {
    CreateScheduleRequest request =
        new CreateScheduleRequest(null, 7L, "http_headers", Map.of(), null, 3600L, true);

    ApiException exception = assertThrows(ApiException.class, () -> service.create(request));

    assertEquals("必须指定评估项目", exception.getMessage());
    verify(projects, never()).validateProjectTarget(any(), any());
    verify(repository, never()).save(any());
  }

  @Test
  void rejectsIntervalShorterThanSixtySecondsAtServiceBoundary() {
    CreateScheduleRequest request =
        new CreateScheduleRequest(5L, 7L, "http_headers", Map.of(), null, 59L, true);

    ApiException exception = assertThrows(ApiException.class, () -> service.create(request));

    assertEquals("周期扫描间隔不能小于 60 秒", exception.getMessage());
    verify(projects, never()).validateProjectTarget(any(), any());
    verify(repository, never()).save(any());
  }

  @Test
  void rejectsCronWhoseAdjacentExecutionsAreLessThanSixtySecondsApart() {
    CreateScheduleRequest request = cronRequest("*/30 * * * * *");

    ApiException exception = assertThrows(ApiException.class, () -> service.create(request));

    assertEquals("Cron 相邻触发间隔不能小于 60 秒", exception.getMessage());
    verify(projects, never()).validateProjectTarget(any(), any());
    verify(repository, never()).save(any());
  }

  @Test
  void rejectsInvalidCronExpressionInChinese() {
    ApiException exception =
        assertThrows(ApiException.class, () -> service.create(cronRequest("invalid cron")));

    assertEquals("Cron 表达式无效", exception.getMessage());
    verify(projects, never()).validateProjectTarget(any(), any());
  }

  @Test
  void rejectsRequestWithBothCronAndInterval() {
    CreateScheduleRequest request =
        new CreateScheduleRequest(5L, 7L, "http_headers", Map.of(), "0 * * * * *", 3600L, true);

    ApiException exception = assertThrows(ApiException.class, () -> service.create(request));

    assertEquals("必须且只能设置 Cron 表达式或执行间隔", exception.getMessage());
    verify(projects, never()).validateProjectTarget(any(), any());
  }

  @Test
  void acceptsCronWithOneMinuteSpacing() {
    ScanSchedule created = service.create(cronRequest("0 * * * * *"));

    assertEquals("0 * * * * *", created.getCronExpression());
    assertEquals(5L, created.getProjectId());
    assertNotNull(created.getNextRunAt());
    verify(repository).save(created);
  }

  private CreateScheduleRequest intervalRequest(Map<String, Object> parameters, Boolean enabled) {
    return new CreateScheduleRequest(5L, 7L, "http_headers", parameters, null, 3600L, enabled);
  }

  private CreateScheduleRequest cronRequest(String cronExpression) {
    return new CreateScheduleRequest(5L, 7L, "http_headers", Map.of(), cronExpression, null, true);
  }

  private ScanSchedule intervalSchedule(Long id) {
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
}
