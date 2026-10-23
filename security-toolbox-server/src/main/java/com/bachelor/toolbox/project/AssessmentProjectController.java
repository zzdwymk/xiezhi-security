package com.bachelor.toolbox.project;

import com.bachelor.toolbox.audit.AuditLog;
import com.bachelor.toolbox.finding.Finding;
import com.bachelor.toolbox.task.ProjectBatchTaskRequest;
import com.bachelor.toolbox.task.ProjectBatchTaskResult;
import com.bachelor.toolbox.task.SecurityTask;
import com.bachelor.toolbox.task.TaskService;
import jakarta.validation.Valid;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/projects")
public class AssessmentProjectController {
  private static final Logger log = LoggerFactory.getLogger(AssessmentProjectController.class);
  private final AssessmentProjectService service;
  private final TaskService taskService;

  @org.springframework.beans.factory.annotation.Autowired
  public AssessmentProjectController(
      AssessmentProjectService service, TaskService taskService) {
    this.service = service;
    this.taskService = taskService;
  }

  /**
   * 兼容既有契约测试（仅构造、不调用批量端点）。
   *
   * <p>显式标注非 Spring 装配构造器，避免容器在多构造器场景下无法选择主构造器。
   */
  public AssessmentProjectController(AssessmentProjectService service) {
    this(service, null);
  }

  @GetMapping
  public List<AssessmentProject> list() {
    return service.list();
  }

  @GetMapping("/{id}")
  public AssessmentProject get(@PathVariable Long id) {
    return service.get(id);
  }

  @PostMapping
  @ResponseStatus(HttpStatus.CREATED)
  public AssessmentProject create(@Valid @RequestBody ProjectDtos.Create request) {
    return service.create(request);
  }

  @PutMapping("/{id}")
  public AssessmentProject update(
      @PathVariable Long id, @Valid @RequestBody ProjectDtos.Update request) {
    return service.update(id, request);
  }

  @PostMapping("/{id}/status")
  public AssessmentProject status(
      @PathVariable Long id, @Valid @RequestBody ProjectDtos.Status request) {
    return service.updateStatus(id, request.status());
  }

  @GetMapping("/{id}/summary")
  public ProjectDtos.Summary summary(@PathVariable Long id) {
    return service.summary(id);
  }

  @GetMapping("/{id}/tasks")
  public List<SecurityTask> tasks(@PathVariable Long id) {
    return service.projectTasks(id);
  }

  @GetMapping("/{id}/findings")
  public List<Finding> findings(@PathVariable Long id) {
    return service.projectFindings(id);
  }

  @GetMapping("/{id}/audits")
  public List<AuditLog> audits(@PathVariable Long id) {
    return service.projectAudits(id);
  }

  @GetMapping("/{id}/targets")
  public List<ProjectTarget> targets(@PathVariable Long id) {
    try {
      return service.targets(id);
    } catch (RuntimeException ex) {
      log.error("加载项目 {} 的目标关联失败", id, ex);
      throw ex;
    }
  }

  @PostMapping("/{id}/targets/{targetId}")
  @ResponseStatus(HttpStatus.CREATED)
  public ProjectTarget addTarget(@PathVariable Long id, @PathVariable Long targetId) {
    return service.addTarget(id, targetId);
  }

  /**
   * 直接按授权项目对项目内目标批量下发同一工具。请求体 {@code projectId} 必须与路径一致； {@code targetIds}
   * 为空表示对项目内全部目标执行。返回逐目标结果以支持部分成功。
   */
  @PostMapping("/{id}/tasks/batch")
  public ProjectBatchTaskResult batchCreateTasks(
      @PathVariable Long id, @Valid @RequestBody ProjectBatchTaskRequest request) {
    if (request.projectId() == null) {
      throw new com.bachelor.toolbox.common.ApiException("项目 ID 不能为空");
    }
    if (!id.equals(request.projectId())) {
      throw new com.bachelor.toolbox.common.ApiException("路径项目 ID 与请求体项目 ID 不一致");
    }
    if (taskService == null) {
      throw new com.bachelor.toolbox.common.ApiException("批量执行能力未配置");
    }
    return taskService.createBatchForProject(request);
  }

  @DeleteMapping("/{id}/targets/{targetId}")
  @ResponseStatus(HttpStatus.NO_CONTENT)
  public void removeTarget(@PathVariable Long id, @PathVariable Long targetId) {
    service.removeTarget(id, targetId);
  }
}
