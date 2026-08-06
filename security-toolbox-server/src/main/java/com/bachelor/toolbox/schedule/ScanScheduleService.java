package com.bachelor.toolbox.schedule;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.common.PageRequests;
import com.bachelor.toolbox.project.AssessmentProjectService;
import com.bachelor.toolbox.project.ProjectAuthorizationService;
import com.bachelor.toolbox.target.TargetService;
import com.bachelor.toolbox.task.CreateTaskRequest;
import com.bachelor.toolbox.task.SecurityTask;
import com.bachelor.toolbox.task.TaskService;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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
  private static final TypeReference<Map<String, Object>> PARAMETERS_TYPE =
      new TypeReference<>() {};

  private final ScanScheduleRepository repository;
  private final TaskService taskService;
  private final TargetService targetService;
  private final AssessmentProjectService projectService;
  private final ProjectAuthorizationService authorization;
  private final ObjectMapper objectMapper;

  public ScanScheduleService(
      ScanScheduleRepository repository,
      TaskService taskService,
      TargetService targetService,
      AssessmentProjectService projectService,
      ProjectAuthorizationService authorization,
      ObjectMapper objectMapper) {
    this.repository = repository;
    this.taskService = taskService;
    this.targetService = targetService;
    this.projectService = projectService;
    this.authorization = authorization;
    this.objectMapper = objectMapper;
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

    ScanSchedule schedule = buildSchedule(request);
    return repository.save(schedule);
  }

  @Transactional
  public ScanSchedule toggle(Long id, boolean enabled) {
    ScanSchedule schedule = load(id);
    authorization.requireManage(schedule.getProjectId());
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

  private ScanSchedule buildSchedule(CreateScheduleRequest request) {
    ScanSchedule schedule = new ScanSchedule();
    schedule.setProjectId(request.projectId());
    schedule.setTargetId(request.targetId());
    schedule.setToolCode(request.toolCode());
    schedule.setParametersJson(serializeParameters(request.parameters()));
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

  private void dispatchSchedule(ScanSchedule schedule, Instant dispatchTime) {
    try {
      Map<String, Object> parameters = deserializeParameters(schedule.getParametersJson());
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
      advanceSchedule(schedule, dispatchTime);
    } catch (Exception exception) {
      advanceSchedule(schedule, dispatchTime);
      log.warn("扫描计划调度失败，已推进到下次执行时间：scheduleId={}", schedule.getId(), exception);
    }
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
