package com.bachelor.toolbox.project;

import com.bachelor.toolbox.audit.AuditLog;
import com.bachelor.toolbox.finding.Finding;
import com.bachelor.toolbox.task.SecurityTask;
import jakarta.validation.Valid;
import java.util.List;
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
  private final AssessmentProjectService service;

  public AssessmentProjectController(AssessmentProjectService service) {
    this.service = service;
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
    return service.targets(id);
  }

  @PostMapping("/{id}/targets/{targetId}")
  @ResponseStatus(HttpStatus.CREATED)
  public ProjectTarget addTarget(@PathVariable Long id, @PathVariable Long targetId) {
    return service.addTarget(id, targetId);
  }

  @DeleteMapping("/{id}/targets/{targetId}")
  @ResponseStatus(HttpStatus.NO_CONTENT)
  public void removeTarget(@PathVariable Long id, @PathVariable Long targetId) {
    service.removeTarget(id, targetId);
  }
}
