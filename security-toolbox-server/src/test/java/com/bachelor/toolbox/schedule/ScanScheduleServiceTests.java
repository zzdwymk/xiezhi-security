package com.bachelor.toolbox.schedule;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
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
import com.bachelor.toolbox.tool.ScannerPocSelectionService;
import com.bachelor.toolbox.tool.SecurityToolRegistry;
import com.bachelor.toolbox.vulnerability.NucleiTemplateCatalogService;
import com.bachelor.toolbox.vulnerability.ScannerPocCatalogService;
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
  private final SecurityToolRegistry toolRegistry = mock(SecurityToolRegistry.class);
  private final ScannerPocSelectionService scannerPocs = mock(ScannerPocSelectionService.class);
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
  void acceptsHttpSecurityCheckWithSupportedCheckParameter() {
    CreateScheduleRequest request =
        new CreateScheduleRequest(
            5L,
            7L,
            "http_security_check",
            Map.of("check", "cors"),
            null,
            3600L,
            true);

    ScanSchedule created = service.create(request);

    assertEquals("http_security_check", created.getToolCode());
    assertEquals("{\"check\":\"cors\"}", created.getParametersJson());
    verify(toolRegistry).require("http_security_check");
  }

  @Test
  void rejectsHttpSecurityCheckWithoutExactlyOneSupportedCheck() {
    for (Map<String, Object> parameters :
        List.<Map<String, Object>>of(
            Map.of(),
            Map.of("check", "cookies", "extra", true),
            Map.of("check", "unknown"))) {
      CreateScheduleRequest request =
          new CreateScheduleRequest(
              5L, 7L, "http_security_check", parameters, null, 3600L, true);

      assertThrows(ApiException.class, () -> service.create(request));
    }

    verify(repository, never()).save(any());
  }

  @Test
  void validatesScannerSelectionsUsingEachExecutorsSelectionContract() {
    service.create(
        new CreateScheduleRequest(
            5L,
            7L,
            "nuclei_scan",
            Map.of("pocCodes", List.of("NU-0123456789ABCDEF01234567")),
            null,
            3600L,
            true));
    service.create(
        new CreateScheduleRequest(
            5L,
            7L,
            "afrog_scan",
            Map.of("pocCodes", List.of("AF-0123456789ABCDEF01234567")),
            null,
            3600L,
            true));
    service.create(
        new CreateScheduleRequest(
            5L,
            7L,
            "xray_scan",
            Map.of("pocCodes", List.of("XR-0123456789ABCDEF01234567")),
            null,
            3600L,
            true));

    verify(scannerPocs)
        .resolve(
            NucleiTemplateCatalogService.SOURCE_TYPE,
            Map.of(
                "pocCodes",
                List.of("NU-0123456789ABCDEF01234567"),
                ScannerPocSelectionService.SAFE_ONLY_PARAMETER,
                true),
            false);
    verify(scannerPocs)
        .resolve(
            ScannerPocCatalogService.AFROG,
            Map.of(
                "pocCodes",
                List.of("AF-0123456789ABCDEF01234567"),
                ScannerPocSelectionService.SAFE_ONLY_PARAMETER,
                true),
            false);
    verify(scannerPocs)
        .resolve(
            ScannerPocCatalogService.XRAY,
            Map.of(
                "pocCodes",
                List.of("XR-0123456789ABCDEF01234567"),
                ScannerPocSelectionService.SAFE_ONLY_PARAMETER,
                true),
            false);
  }

  @Test
  void rejectsDynamicAllPocsForUnattendedSchedules() {
    CreateScheduleRequest request =
        new CreateScheduleRequest(
            5L, 7L, "afrog_scan", Map.of("allPocs", true), null, 3600L, true);

    ApiException exception = assertThrows(ApiException.class, () -> service.create(request));

    assertEquals("定时扫描不支持动态全部 PoC，请明确选择 SAFE PoC", exception.getMessage());
    verify(scannerPocs, never()).resolve(any(), any(), eq(false));
    verify(repository, never()).save(any());
  }

  @Test
  void rejectsEmptyNucleiSelectionForUnattendedSchedules() {
    doThrow(new ApiException("请至少选择一个 NUCLEI PoC"))
        .when(scannerPocs)
        .resolve(
            eq(NucleiTemplateCatalogService.SOURCE_TYPE),
            eq(Map.of(ScannerPocSelectionService.SAFE_ONLY_PARAMETER, true)),
            eq(false));
    CreateScheduleRequest request =
        new CreateScheduleRequest(5L, 7L, "nuclei_scan", Map.of(), null, 3600L, true);

    ApiException exception = assertThrows(ApiException.class, () -> service.create(request));

    assertEquals("请至少选择一个 NUCLEI PoC", exception.getMessage());
    verify(repository, never()).save(any());
  }

  @Test
  void rejectsScannerScheduleWhenPocSelectionValidationFails() {
    doThrow(new ApiException("请至少选择一个 AFROG PoC"))
        .when(scannerPocs)
        .resolve(
            eq(ScannerPocCatalogService.AFROG),
            eq(Map.of(ScannerPocSelectionService.SAFE_ONLY_PARAMETER, true)),
            eq(false));
    CreateScheduleRequest request =
        new CreateScheduleRequest(5L, 7L, "afrog_scan", Map.of(), null, 3600L, true);

    ApiException exception = assertThrows(ApiException.class, () -> service.create(request));

    assertEquals("请至少选择一个 AFROG PoC", exception.getMessage());
    verify(repository, never()).save(any());
  }

  @Test
  void rejectsToolsOutsideScheduledExecutionAllowlist() {
    CreateScheduleRequest request =
        new CreateScheduleRequest(
            5L, 7L, "retrieve_project_context", Map.of(), null, 3600L, true);

    ApiException exception = assertThrows(ApiException.class, () -> service.create(request));

    assertEquals("该工具不支持定时执行: retrieve_project_context", exception.getMessage());
    verify(toolRegistry, never()).require(any());
    verify(repository, never()).save(any());
  }

  @Test
  void enablingScannerScheduleRevalidatesPersistedPocSelection() {
    ScanSchedule schedule = intervalSchedule(11L);
    schedule.setEnabled(false);
    schedule.setToolCode("xray_scan");
    schedule.setParametersJson("{\"pocCodes\":[\"XR-0123456789ABCDEF01234567\"]}");
    when(repository.findById(11L)).thenReturn(Optional.of(schedule));

    ScanSchedule enabled = service.toggle(11L, true);

    assertTrue(enabled.isEnabled());
    assertEquals(
        "{\"pocCodes\":[\"XR-0123456789ABCDEF01234567\"],\"scheduledSafeOnly\":true}",
        enabled.getParametersJson());
    verify(toolRegistry).require("xray_scan");
    verify(scannerPocs)
        .resolve(
            ScannerPocCatalogService.XRAY,
            Map.of(
                "pocCodes",
                List.of("XR-0123456789ABCDEF01234567"),
                ScannerPocSelectionService.SAFE_ONLY_PARAMETER,
                true),
            false);
  }

  @Test
  void refusesToEnableScheduleAfterTargetIsRemovedFromProject() {
    ScanSchedule schedule = intervalSchedule(11L);
    schedule.setEnabled(false);
    when(repository.findById(11L)).thenReturn(Optional.of(schedule));
    doThrow(new ApiException("目标不属于该评估项目"))
        .when(projects)
        .validateProjectTarget(5L, 7L);

    ApiException exception =
        assertThrows(ApiException.class, () -> service.toggle(11L, true));

    assertEquals("目标不属于该评估项目", exception.getMessage());
    assertFalse(schedule.isEnabled());
    verify(targets, never()).getCurrentlyAuthorized(7L);
    verify(repository, never()).save(schedule);
  }

  @Test
  void refusesToEnableScheduleAfterTargetAuthorizationExpires() {
    ScanSchedule schedule = intervalSchedule(11L);
    schedule.setEnabled(false);
    when(repository.findById(11L)).thenReturn(Optional.of(schedule));
    doThrow(new ApiException("授权已过期"))
        .when(targets)
        .getCurrentlyAuthorized(7L);

    ApiException exception =
        assertThrows(ApiException.class, () -> service.toggle(11L, true));

    assertEquals("授权已过期", exception.getMessage());
    assertFalse(schedule.isEnabled());
    verify(projects).validateProjectTarget(5L, 7L);
    verify(toolRegistry, never()).require(any());
    verify(repository, never()).save(schedule);
  }

  @Test
  void refusesToEnableScannerScheduleAfterItsPocSelectionBecomesInvalid() {
    ScanSchedule schedule = intervalSchedule(11L);
    schedule.setEnabled(false);
    schedule.setToolCode("afrog_scan");
    schedule.setParametersJson("{\"pocCodes\":[\"AF-0123456789ABCDEF01234567\"]}");
    when(repository.findById(11L)).thenReturn(Optional.of(schedule));
    doThrow(new ApiException("PoC 文件已变化，请重新同步漏洞库"))
        .when(scannerPocs)
        .resolve(
            eq(ScannerPocCatalogService.AFROG),
            eq(
                Map.of(
                    "pocCodes",
                    List.of("AF-0123456789ABCDEF01234567"),
                    ScannerPocSelectionService.SAFE_ONLY_PARAMETER,
                    true)),
            eq(false));

    ApiException exception =
        assertThrows(ApiException.class, () -> service.toggle(11L, true));

    assertEquals("PoC 文件已变化，请重新同步漏洞库", exception.getMessage());
    assertFalse(schedule.isEnabled());
    verify(repository, never()).save(schedule);
  }

  @Test
  void reportsParameterSerializationFailureInChinese() throws Exception {
    ObjectMapper failingMapper = mock(ObjectMapper.class);
    when(failingMapper.writeValueAsString(any()))
        .thenThrow(new JsonProcessingException("serialization failed") {});
    ScanScheduleService failingService =
        new ScanScheduleService(
            repository,
            tasks,
            targets,
            projects,
            authorization,
            failingMapper,
            toolRegistry,
            scannerPocs);

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
    schedule.setToolCode("xray_scan");
    schedule.setParametersJson("{\"pocCodes\":[\"XR-0123456789ABCDEF01234567\"]}");
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
    verify(authorization, times(2)).callWithSystemAccess(any());
    CreateTaskRequest request = requestCaptor.getValue();
    assertEquals(5L, request.projectId());
    assertEquals(7L, request.targetId());
    assertEquals("xray_scan", request.toolCode());
    assertEquals(
        Map.of(
            "pocCodes",
            List.of("XR-0123456789ABCDEF01234567"),
            ScannerPocSelectionService.SAFE_ONLY_PARAMETER,
            true),
        request.parameters());
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
    assertEquals("任务创建失败", schedule.getLastError());
    assertTrue(schedule.isEnabled());
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
    assertNull(malformed.getNextRunAt());
    assertFalse(malformed.isEnabled());
    assertEquals("扫描参数无效", malformed.getLastError());
    assertNotNull(valid.getLastRunAt());
    assertEquals(92L, valid.getLastTaskId());
    verify(tasks).create(any(CreateTaskRequest.class));
    verify(repository).save(malformed);
    verify(repository).save(valid);
  }

  @Test
  void dispatchDisablesScheduleWhenPersistedHttpParametersAreInvalid() throws Exception {
    ScanSchedule invalid = intervalSchedule(11L);
    invalid.setToolCode("http_security_check");
    invalid.setParametersJson("{\"check\":\"unknown\"}");
    when(repository.findByEnabledTrueAndNextRunAtLessThanEqual(
            any(Instant.class), any(Pageable.class)))
        .thenReturn(List.of(invalid));

    service.dispatch();

    assertFalse(invalid.isEnabled());
    assertNull(invalid.getNextRunAt());
    assertEquals("不支持的 HTTP 检查类型: unknown", invalid.getLastError());
    verify(tasks, never()).create(any());
    verify(repository).save(invalid);
  }

  @Test
  void dispatchDisablesScannerScheduleWhenSafePocRevalidationFails() throws Exception {
    ScanSchedule invalid = intervalSchedule(11L);
    invalid.setToolCode("xray_scan");
    invalid.setParametersJson("{\"pocCodes\":[\"XR-0123456789ABCDEF01234567\"]}");
    Map<String, Object> normalized =
        Map.of(
            "pocCodes",
            List.of("XR-0123456789ABCDEF01234567"),
            ScannerPocSelectionService.SAFE_ONLY_PARAMETER,
            true);
    doThrow(new ApiException("定时扫描仅允许执行标记为 SAFE 的 PoC"))
        .when(scannerPocs)
        .resolve(ScannerPocCatalogService.XRAY, normalized, false);
    when(repository.findByEnabledTrueAndNextRunAtLessThanEqual(
            any(Instant.class), any(Pageable.class)))
        .thenReturn(List.of(invalid));

    service.dispatch();

    assertFalse(invalid.isEnabled());
    assertNull(invalid.getNextRunAt());
    assertEquals("定时扫描仅允许执行标记为 SAFE 的 PoC", invalid.getLastError());
    verify(tasks, never()).create(any());
    verify(repository).save(invalid);
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
