package com.bachelor.toolbox.schedule;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.project.AssessmentProjectService;
import com.bachelor.toolbox.project.ProjectAuthorizationService;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.TargetService;
import com.bachelor.toolbox.task.CreateTaskRequest;
import com.bachelor.toolbox.task.SecurityTask;
import com.bachelor.toolbox.task.SecurityTaskRepository;
import com.bachelor.toolbox.task.TaskExecutionControlService;
import com.bachelor.toolbox.task.TaskExecutionService;
import com.bachelor.toolbox.task.TaskProgressEventService;
import com.bachelor.toolbox.task.TaskService;
import com.bachelor.toolbox.task.TaskSnapshotService;
import com.bachelor.toolbox.tool.ScannerPocSelectionService;
import com.bachelor.toolbox.tool.SecurityToolRegistry;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.Callable;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.data.domain.Pageable;

/** Round 398: scheduler boundaries use real policy checks and mocked execution; no network. */
class ScanScheduleParameterBoundaryTests {
  private static final String SAFE_ONLY = ScannerPocSelectionService.SAFE_ONLY_PARAMETER;
  private static final Map<String, String> SCANNER_CODES = Map.of(
      "nuclei_scan", "NU-0123456789ABCDEF01234567",
      "afrog_scan", "AF-0123456789ABCDEF01234567",
      "xray_scan", "XR-0123456789ABCDEF01234567");
  private final ScanScheduleRepository repository = mock(ScanScheduleRepository.class);
  private final TaskService tasks = mock(TaskService.class);
  private final TargetService targets = mock(TargetService.class);
  private final AssessmentProjectService projects = mock(AssessmentProjectService.class);
  private final ProjectAuthorizationService authorization = mock(ProjectAuthorizationService.class);
  private final SecurityToolRegistry registry = mock(SecurityToolRegistry.class);
  private final ScannerPocSelectionService scannerPocs = mock(ScannerPocSelectionService.class);
  private final ObjectMapper mapper = new ObjectMapper();
  private ScanScheduleService service;

  @BeforeEach
  void setUp() throws Exception {
    service = new ScanScheduleService(repository, tasks, targets, projects, authorization,
        mapper, registry, scannerPocs);
    when(authorization.callWithSystemAccess(any())).thenAnswer(invocation -> {
      Callable<?> operation = invocation.getArgument(0);
      return operation.call();
    });
    when(repository.save(any(ScanSchedule.class))).thenAnswer(invocation -> invocation.getArgument(0));
    when(targets.getCurrentlyAuthorized(7L)).thenReturn(target());
  }

  @Test
  void createRejectsUserInternalChannelsBeforeAuthorizationOrPersistence() {
    for (Map<String, Object> parameters : List.<Map<String, Object>>of(
        Map.of("__resolvedWebBases", List.of("http://192.168.222.155:8080/")),
        Map.of("__unrecognizedInternalChannel", true))) {
      ApiException exception = assertThrows(ApiException.class,
          () -> service.create(request("http_headers", parameters)));
      assertTrue(exception.getMessage().contains("内部保留键"));
    }
    for (String tool : SCANNER_CODES.keySet()) {
      for (boolean userValue : new boolean[] {false, true}) {
        Map<String, Object> parameters = new LinkedHashMap<>(scannerParameters(tool));
        parameters.put(SAFE_ONLY, userValue);
        ApiException exception = assertThrows(ApiException.class,
            () -> service.create(request(tool, parameters)));
        assertTrue(exception.getMessage().contains("内部保留键"));
      }
    }
    verify(projects, never()).validateProjectTarget(any(), any());
    verify(repository, never()).save(any());
  }

  @Test
  void createRejectsUnknownOptionsAndInvalidEnumsUsingCentralPolicy() {
    for (CreateScheduleRequest request : List.of(
        request("http_headers", Map.of("depth", 2)),
        request("http_headers", Map.of("path", "/admin")),
        request("tls_config", Map.of("port", 443)),
        request("tcp_ports", Map.of("mode", "quick")),
        request("nmap_service_scan", Map.of("mode", "not-a-mode")),
        request("zap_scan", Map.of("extra", true)),
        request("xray_scan", Map.of("pocCodes", List.of(SCANNER_CODES.get("xray_scan")), "extra", true)))) {
      assertThrows(ApiException.class, () -> service.create(request));
    }
    verify(repository, never()).save(any());
  }

  @Test
  void enableRejectsStoredInternalChannelsWithoutChangingPlanOrCreatingTask() throws Exception {
    long id = 20L;
    for (Map<String, Object> parameters : List.<Map<String, Object>>of(
        Map.of("__resolvedWebBases", List.of("http://192.168.222.155:8080/")),
        Map.of("__unrecognizedInternalChannel", true))) {
      ScanSchedule schedule = schedule(id++, "http_headers", parameters, false);
      when(repository.findById(schedule.getId())).thenReturn(Optional.of(schedule));
      assertThrows(ApiException.class, () -> service.toggle(schedule.getId(), true));
      assertFalse(schedule.isEnabled());
      assertNull(schedule.getNextRunAt());
    }
    verify(repository, never()).save(any());
    verify(tasks, never()).create(any());
  }

  @Test
  void storedSafeFlagDoesNotMakeOtherInternalChannelsTrusted() throws Exception {
    Map<String, Object> parameters = new LinkedHashMap<>(scannerParameters("xray_scan"));
    parameters.put(SAFE_ONLY, true);
    parameters.put("__resolvedWebBases", List.of("http://192.168.222.155:8080/"));
    ScanSchedule schedule = schedule(21L, "xray_scan", parameters, false);
    when(repository.findById(21L)).thenReturn(Optional.of(schedule));

    ApiException exception = assertThrows(ApiException.class, () -> service.toggle(21L, true));

    assertTrue(exception.getMessage().contains("内部保留键"));
    assertFalse(schedule.isEnabled());
    verify(repository, never()).save(any());
    verify(tasks, never()).create(any());
  }

  @Test
  void enableRejectsStoredUnknownOptionsWithoutChangingPlan() throws Exception {
    ScanSchedule schedule = schedule(22L, "http_headers", Map.of("depth", 2), false);
    when(repository.findById(22L)).thenReturn(Optional.of(schedule));

    ApiException exception = assertThrows(ApiException.class, () -> service.toggle(22L, true));

    assertTrue(exception.getMessage().contains("depth"));
    assertFalse(schedule.isEnabled());
    verify(repository, never()).save(any());
    verify(tasks, never()).create(any());
  }

  @Test
  void enableRejectsNonCanonicalSafeFlagsAndFlagsOnNonScannerTools() throws Exception {
    List<ScanSchedule> invalid = new ArrayList<>();
    long id = 30L;
    for (Object value : List.of(false, "true", 1)) {
      Map<String, Object> parameters = new LinkedHashMap<>(scannerParameters("nuclei_scan"));
      parameters.put(SAFE_ONLY, value);
      invalid.add(schedule(id++, "nuclei_scan", parameters, false));
    }
    invalid.add(schedule(id, "http_headers", Map.of(SAFE_ONLY, true), false));
    for (ScanSchedule schedule : invalid) {
      when(repository.findById(schedule.getId())).thenReturn(Optional.of(schedule));
      assertThrows(ApiException.class, () -> service.toggle(schedule.getId(), true));
      assertFalse(schedule.isEnabled());
      assertNull(schedule.getNextRunAt());
    }
    verify(repository, never()).save(any());
    verify(tasks, never()).create(any());
  }

  @Test
  void dispatchDisablesInvalidStoredPlansAndContinuesWithValidPlan() throws Exception {
    List<ScanSchedule> invalid = new ArrayList<>();
    invalid.add(schedule(40L, "http_headers",
        Map.of("__resolvedWebBases", List.of("http://192.168.222.155:8080/")), true));
    invalid.add(schedule(41L, "tls_config", Map.of("__unrecognizedInternalChannel", true), true));
    invalid.add(schedule(42L, "http_headers", Map.of("depth", 2), true));
    invalid.add(schedule(43L, "http_headers", Map.of(SAFE_ONLY, true), true));
    Map<String, Object> unsafeScanner = new LinkedHashMap<>(scannerParameters("afrog_scan"));
    unsafeScanner.put(SAFE_ONLY, false);
    invalid.add(schedule(44L, "afrog_scan", unsafeScanner, true));
    ScanSchedule valid = schedule(45L, "http_headers", Map.of(), true);
    List<ScanSchedule> due = new ArrayList<>(invalid);
    due.add(valid);
    when(repository.findByEnabledTrueAndNextRunAtLessThanEqual(any(Instant.class), any(Pageable.class)))
        .thenReturn(due);
    SecurityTask created = new SecurityTask();
    created.setId(91L);
    when(tasks.create(any(CreateTaskRequest.class))).thenReturn(created);

    service.dispatch();

    for (ScanSchedule schedule : invalid) {
      assertFalse(schedule.isEnabled());
      assertNull(schedule.getNextRunAt());
      assertNull(schedule.getLastTaskId());
      assertNull(schedule.getLastRunAt());
      assertNotNull(schedule.getLastError());
      verify(repository).save(schedule);
    }
    ArgumentCaptor<CreateTaskRequest> captor = ArgumentCaptor.forClass(CreateTaskRequest.class);
    verify(tasks).create(captor.capture());
    assertEquals("http_headers", captor.getValue().toolCode());
    assertEquals(Map.of(), captor.getValue().parameters());
    assertEquals(91L, valid.getLastTaskId());
    assertTrue(valid.isEnabled());
  }

  @Test
  void canonicalStoredScannerFlagSurvivesEnableAndDispatchForEveryScanner() throws Exception {
    List<ScanSchedule> schedules = new ArrayList<>();
    long id = 50L;
    for (String tool : SCANNER_CODES.keySet()) {
      Map<String, Object> parameters = new LinkedHashMap<>(scannerParameters(tool));
      parameters.put(SAFE_ONLY, true);
      ScanSchedule schedule = schedule(id++, tool, parameters, false);
      when(repository.findById(schedule.getId())).thenReturn(Optional.of(schedule));
      service.toggle(schedule.getId(), true);
      assertTrue(schedule.isEnabled());
      assertTrue(mapper.readTree(schedule.getParametersJson()).path(SAFE_ONLY).asBoolean());
      schedules.add(schedule);
    }
    when(repository.findByEnabledTrueAndNextRunAtLessThanEqual(any(Instant.class), any(Pageable.class)))
        .thenReturn(schedules);
    SecurityTask created = new SecurityTask();
    created.setId(92L);
    when(tasks.create(any(CreateTaskRequest.class))).thenReturn(created);

    service.dispatch();

    ArgumentCaptor<CreateTaskRequest> captor = ArgumentCaptor.forClass(CreateTaskRequest.class);
    verify(tasks, times(3)).create(captor.capture());
    for (CreateTaskRequest request : captor.getAllValues()) {
      assertEquals(true, request.parameters().get(SAFE_ONLY));
      assertEquals(List.of(SCANNER_CODES.get(request.toolCode())), request.parameters().get("pocCodes"));
    }
    for (ScanSchedule schedule : schedules) {
      assertTrue(schedule.isEnabled());
      assertNull(schedule.getLastError());
      assertEquals(92L, schedule.getLastTaskId());
    }
  }

  @Test
  void dispatchPassesTrustedSafeFlagThroughRealTaskServicePolicyWithoutStartingExecution() throws Exception {
    SecurityTaskRepository taskRepository = mock(SecurityTaskRepository.class);
    TaskExecutionService execution = mock(TaskExecutionService.class);
    TaskService realTasks = new TaskService(taskRepository, targets, registry, execution,
        mock(AuditService.class), mapper, mock(TaskSnapshotService.class),
        mock(TaskExecutionControlService.class), projects, mock(TaskProgressEventService.class), event -> {});
    when(targets.getCurrentlyAuthorized(7L, 5L)).thenReturn(target());
    when(taskRepository.save(any(SecurityTask.class))).thenAnswer(invocation -> {
      SecurityTask task = invocation.getArgument(0);
      task.setId(100L);
      return task;
    });
    ScanScheduleService realFunnel = new ScanScheduleService(repository, realTasks, targets, projects,
        authorization, mapper, registry, scannerPocs);
    List<ScanSchedule> schedules = new ArrayList<>();
    long id = 60L;
    for (String tool : SCANNER_CODES.keySet()) {
      schedules.add(schedule(id++, tool, scannerParameters(tool), true));
    }
    when(repository.findByEnabledTrueAndNextRunAtLessThanEqual(any(Instant.class), any(Pageable.class)))
        .thenReturn(schedules);

    realFunnel.dispatch();

    ArgumentCaptor<SecurityTask> captor = ArgumentCaptor.forClass(SecurityTask.class);
    verify(taskRepository, times(3)).save(captor.capture());
    for (SecurityTask task : captor.getAllValues()) {
      assertTrue(mapper.readTree(task.getRequestJson()).path(SAFE_ONLY).asBoolean());
      assertEquals("PENDING", task.getStatus());
    }
    verify(execution, times(3)).executeAsync(100L);
    for (ScanSchedule schedule : schedules) {
      assertNull(schedule.getLastError());
      assertEquals(100L, schedule.getLastTaskId());
    }
  }

  private CreateScheduleRequest request(String tool, Map<String, Object> parameters) {
    return new CreateScheduleRequest(5L, 7L, tool, parameters, null, 3600L, true);
  }

  private Map<String, Object> scannerParameters(String tool) {
    return Map.of("pocCodes", List.of(SCANNER_CODES.get(tool)));
  }

  private ScanSchedule schedule(Long id, String tool, Map<String, Object> parameters, boolean enabled)
      throws Exception {
    ScanSchedule schedule = new ScanSchedule();
    schedule.setId(id);
    schedule.setProjectId(5L);
    schedule.setTargetId(7L);
    schedule.setToolCode(tool);
    schedule.setParametersJson(mapper.writeValueAsString(parameters));
    schedule.setIntervalSeconds(3600L);
    schedule.setEnabled(enabled);
    schedule.setNextRunAt(enabled ? Instant.now().minusSeconds(1) : null);
    return schedule;
  }

  private AuthorizedTarget target() {
    AuthorizedTarget target = new AuthorizedTarget();
    target.setId(7L);
    target.setTargetValue("192.168.222.155");
    target.setTargetType("IP");
    target.setAllowedPorts("80,443");
    target.setEnabled(true);
    return target;
  }
}
