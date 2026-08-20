package com.bachelor.toolbox.schedule;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.common.PageRequests;
import com.bachelor.toolbox.project.AssessmentProjectService;
import com.bachelor.toolbox.project.ProjectAuthorizationService;
import com.bachelor.toolbox.settings.BusinessDataOperationGate;
import com.bachelor.toolbox.target.TargetService;
import com.bachelor.toolbox.task.CreateTaskRequest;
import com.bachelor.toolbox.task.SecurityTask;
import com.bachelor.toolbox.task.TaskService;
import com.bachelor.toolbox.tool.ScannerPocSelectionService;
import com.bachelor.toolbox.tool.SecurityToolRegistry;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Sort;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.scheduling.support.CronExpression;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class ScanScheduleService {
  private static final Logger log = LoggerFactory.getLogger(ScanScheduleService.class);
  private static final Sort LIST_SORT =
      Sort.by(Sort.Order.desc("createdAt"), Sort.Order.desc("id"));
  private static final Sort DISPATCH_SORT =
      Sort.by(Sort.Order.asc("nextRunAt"), Sort.Order.asc("id"));
  private static final long MINIMUM_INTERVAL_SECONDS = 60;
  private static final int CRON_INTERVAL_CHECK_COUNT = 64;
  private static final Set<String> SCHEDULED_TOOL_CODES =
      Set.of(
          "tcp_ports",
          "http_headers",
          "tls_config",
          "nmap_service_scan",
          "http_security_check",
          "nuclei_scan",
          "afrog_scan",
          "xray_scan");
  private static final Set<String> HTTP_SECURITY_CHECKS =
      Set.of("cookies", "cors", "methods", "disclosure");
  private static final TypeReference<Map<String, Object>> PARAMETERS_TYPE =
      new TypeReference<>() {};

  private final ScanScheduleRepository repository;
  private final TaskService taskService;
  private final TargetService targetService;
  private final AssessmentProjectService projectService;
  private final ProjectAuthorizationService authorization;
  private final ObjectMapper objectMapper;
  private final SecurityToolRegistry toolRegistry;
  private final ScannerPocSelectionService scannerPocs;
  private final BusinessDataOperationGate operationGate;

  @Autowired
  public ScanScheduleService(
      ScanScheduleRepository repository,
      TaskService taskService,
      TargetService targetService,
      AssessmentProjectService projectService,
      ProjectAuthorizationService authorization,
      ObjectMapper objectMapper,
      SecurityToolRegistry toolRegistry,
      ScannerPocSelectionService scannerPocs,
      BusinessDataOperationGate operationGate) {
    this.repository = repository;
    this.taskService = taskService;
    this.targetService = targetService;
    this.projectService = projectService;
    this.authorization = authorization;
    this.objectMapper = objectMapper;
    this.toolRegistry = toolRegistry;
    this.scannerPocs = scannerPocs;
    this.operationGate = operationGate;
  }

  ScanScheduleService(
      ScanScheduleRepository repository,
      TaskService taskService,
      TargetService targetService,
      AssessmentProjectService projectService,
      ProjectAuthorizationService authorization,
      ObjectMapper objectMapper,
      SecurityToolRegistry toolRegistry,
      ScannerPocSelectionService scannerPocs) {
    this(
        repository,
        taskService,
        targetService,
        projectService,
        authorization,
        objectMapper,
        toolRegistry,
        scannerPocs,
        new BusinessDataOperationGate());
  }

  public List<ScanSchedule> list() {
    if (authorization.isAdmin()) {
      return repository.findAll(PageRequests.firstPage(LIST_SORT)).getContent();
    }
    return repository
        .findAccessibleByProjectOwner(
            authorization.currentUsername(), PageRequests.firstPage(LIST_SORT))
        .getContent();
  }

  public ScanSchedule get(Long id) {
    ScanSchedule schedule = load(id);
    authorization.requireAccess(schedule.getProjectId());
    return schedule;
  }

  @Transactional
  public ScanSchedule create(CreateScheduleRequest request) {
    validateCreateRequest(request);
    projectService.validateProjectTarget(request.projectId(), request.targetId());
    targetService.getCurrentlyAuthorized(request.targetId());
    Map<String, Object> parameters =
        normalizeScheduledParameters(request.toolCode(), request.parameters());
    validateScheduledTool(request.toolCode(), parameters);

    ScanSchedule schedule = buildSchedule(request, parameters);
    return repository.save(schedule);
  }

  @Transactional
  public ScanSchedule toggle(Long id, boolean enabled) {
    ScanSchedule schedule = load(id);
    authorization.requireManage(schedule.getProjectId());
    if (enabled) {
      projectService.validateProjectTarget(schedule.getProjectId(), schedule.getTargetId());
      targetService.getCurrentlyAuthorized(schedule.getTargetId());
      Map<String, Object> parameters =
          normalizeScheduledParameters(
              schedule.getToolCode(), deserializeStoredParameters(schedule.getParametersJson()));
      validateScheduledTool(schedule.getToolCode(), parameters);
      schedule.setParametersJson(serializeParameters(parameters));
      schedule.setLastError(null);
    }
    schedule.setEnabled(enabled);
    schedule.setNextRunAt(enabled ? calculateNextRun(schedule, Instant.now()) : null);
    return repository.save(schedule);
  }

  public void delete(Long id) {
    ScanSchedule schedule = load(id);
    authorization.requireManage(schedule.getProjectId());
    repository.delete(schedule);
  }

  @Scheduled(fixedDelayString = "${toolbox.scheduler.poll-ms:5000}")
  @Transactional
  public void dispatch() {
    operationGate.withMutation(this::dispatchUnderGate);
  }

  private void dispatchUnderGate() {
    Instant dispatchTime = Instant.now();
    List<ScanSchedule> dueSchedules =
        repository.findByEnabledTrueAndNextRunAtLessThanEqual(
            dispatchTime, PageRequests.firstPage(DISPATCH_SORT));

    for (ScanSchedule schedule : dueSchedules) {
      dispatchSchedule(schedule, dispatchTime);
    }
  }

  private void validateCreateRequest(CreateScheduleRequest request) {
    if (request.projectId() == null) {
      throw new ApiException("必须指定评估项目");
    }
    validateScheduleExpression(request.cronExpression(), request.intervalSeconds());
  }

  private ScanSchedule buildSchedule(
      CreateScheduleRequest request, Map<String, Object> normalizedParameters) {
    ScanSchedule schedule = new ScanSchedule();
    schedule.setProjectId(request.projectId());
    schedule.setTargetId(request.targetId());
    schedule.setToolCode(request.toolCode());
    schedule.setParametersJson(serializeParameters(normalizedParameters));
    schedule.setCronExpression(request.cronExpression());
    schedule.setIntervalSeconds(request.intervalSeconds());
    schedule.setEnabled(request.enabled() == null || request.enabled());
    schedule.setNextRunAt(schedule.isEnabled() ? calculateNextRun(schedule, Instant.now()) : null);
    return schedule;
  }

  private String serializeParameters(Map<String, Object> parameters) {
    try {
      return objectMapper.writeValueAsString(parameters == null ? Map.of() : parameters);
    } catch (Exception exception) {
      throw new ApiException("扫描参数无效");
    }
  }

  private Map<String, Object> deserializeStoredParameters(String parametersJson) {
    try {
      return deserializeParameters(parametersJson);
    } catch (Exception exception) {
      throw new ApiException("扫描参数无效");
    }
  }

  private void validateScheduledTool(String toolCode, Map<String, Object> parameters) {
    if (!SCHEDULED_TOOL_CODES.contains(toolCode)) {
      throw new ApiException("该工具不支持定时执行: " + toolCode);
    }
    toolRegistry.require(toolCode);

    Map<String, Object> safeParameters = parameters == null ? Map.of() : parameters;
    if ("http_security_check".equals(toolCode)) {
      validateHttpSecurityParameters(safeParameters);
      return;
    }

    String scannerSource = ScannerPocSelectionService.sourceForTool(toolCode);
    if (scannerSource != null) {
      scannerPocs.resolve(scannerSource, safeParameters, false);
    }
  }

  private Map<String, Object> normalizeScheduledParameters(
      String toolCode, Map<String, Object> parameters) {
    Map<String, Object> normalized =
        new LinkedHashMap<>(parameters == null ? Map.of() : parameters);
    if (ScannerPocSelectionService.sourceForTool(toolCode) == null) {
      return normalized;
    }
    if (normalized.containsKey(ScannerPocSelectionService.ALL_PARAMETER)) {
      throw new ApiException("定时扫描不支持动态全部 PoC，请明确选择 SAFE PoC");
    }
    normalized.put(ScannerPocSelectionService.SAFE_ONLY_PARAMETER, true);
    return normalized;
  }

  private void validateHttpSecurityParameters(Map<String, Object> parameters) {
    if (parameters.size() != 1 || !parameters.containsKey("check")) {
      throw new ApiException("HTTP 漏洞检查要求且仅允许 check 参数");
    }
    String check =
        Objects.toString(parameters.get("check"), "").trim().toLowerCase(Locale.ROOT);
    if (!HTTP_SECURITY_CHECKS.contains(check)) {
      throw new ApiException("不支持的 HTTP 检查类型: " + check);
    }
  }

  private void dispatchSchedule(ScanSchedule schedule, Instant dispatchTime) {
    Map<String, Object> parameters;
    try {
      parameters =
          normalizeScheduledParameters(
              schedule.getToolCode(), deserializeStoredParameters(schedule.getParametersJson()));
      authorization.callWithSystemAccess(
          () -> {
            projectService.validateProjectTarget(schedule.getProjectId(), schedule.getTargetId());
            targetService.getCurrentlyAuthorized(schedule.getTargetId());
            validateScheduledTool(schedule.getToolCode(), parameters);
            return null;
          });
      schedule.setParametersJson(serializeParameters(parameters));
    } catch (Exception exception) {
      disableInvalidSchedule(schedule, exception);
      return;
    }

    try {
      SecurityTask task =
          authorization.callWithSystemAccess(
              () ->
                  taskService.create(
                      new CreateTaskRequest(
                          schedule.getProjectId(),
                          schedule.getTargetId(),
                          schedule.getToolCode(),
                          parameters)));
      schedule.setLastRunAt(dispatchTime);
      schedule.setLastTaskId(task.getId());
      schedule.setLastError(null);
      advanceSchedule(schedule, dispatchTime);
    } catch (Exception exception) {
      schedule.setLastError(scheduleErrorMessage(exception));
      advanceSchedule(schedule, dispatchTime);
      log.warn("扫描计划调度失败，已推进到下次执行时间：scheduleId={}", schedule.getId(), exception);
    }
  }

  private void disableInvalidSchedule(ScanSchedule schedule, Exception exception) {
    schedule.setEnabled(false);
    schedule.setNextRunAt(null);
    schedule.setLastError(scheduleErrorMessage(exception));
    repository.save(schedule);
    log.warn("扫描计划复验失败，已自动停用：scheduleId={}", schedule.getId(), exception);
  }

  private String scheduleErrorMessage(Exception exception) {
    String message = exception.getMessage();
    if (message == null || message.isBlank()) message = "定时任务执行失败，请查看服务日志";
    return message.length() <= 1000 ? message : message.substring(0, 1000);
  }

  private Map<String, Object> deserializeParameters(String parametersJson) throws Exception {
    return objectMapper.readValue(parametersJson, PARAMETERS_TYPE);
  }

  private ScanSchedule load(Long id) {
    return repository.findById(id).orElseThrow(() -> new ApiException("扫描计划不存在"));
  }

  private void advanceSchedule(ScanSchedule schedule, Instant baseTime) {
    schedule.setNextRunAt(calculateNextRun(schedule, baseTime));
    repository.save(schedule);
  }

  private Instant calculateNextRun(ScanSchedule schedule, Instant baseTime) {
    if (schedule.getIntervalSeconds() != null) {
      return baseTime.plusSeconds(schedule.getIntervalSeconds());
    }

    CronExpression expression = CronExpression.parse(schedule.getCronExpression());
    ZonedDateTime nextRun =
        expression.next(ZonedDateTime.ofInstant(baseTime, ZoneId.systemDefault()));
    return nextRun.toInstant();
  }

  private void validateScheduleExpression(String cronExpression, Long intervalSeconds) {
    if ((cronExpression == null) == (intervalSeconds == null)) {
      throw new ApiException("必须且只能设置 Cron 表达式或执行间隔");
    }
    if (intervalSeconds != null && intervalSeconds < MINIMUM_INTERVAL_SECONDS) {
      throw new ApiException("周期扫描间隔不能小于 60 秒");
    }
    if (cronExpression != null) {
      validateCronExpression(cronExpression);
    }
  }

  private void validateCronExpression(String cronExpression) {
    try {
      CronExpression expression = CronExpression.parse(cronExpression);
      validateCronIntervals(expression);
    } catch (ApiException exception) {
      throw exception;
    } catch (Exception exception) {
      throw new ApiException("Cron 表达式无效");
    }
  }

  private void validateCronIntervals(CronExpression expression) {
    ZonedDateTime current = ZonedDateTime.now(ZoneOffset.UTC).withNano(0);
    Duration minimumInterval = Duration.ofSeconds(MINIMUM_INTERVAL_SECONDS);

    for (int index = 0; index < CRON_INTERVAL_CHECK_COUNT; index++) {
      ZonedDateTime nextRun = expression.next(current);
      if (nextRun == null) {
        return;
      }
      if (index > 0 && Duration.between(current, nextRun).compareTo(minimumInterval) < 0) {
        throw new ApiException("Cron 相邻触发间隔不能小于 60 秒");
      }
      current = nextRun;
    }
  }
}
