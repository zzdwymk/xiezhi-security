package com.bachelor.toolbox.project;

import java.util.List;
import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/projects/{projectId}/approvals")
public class ProjectApprovalController {
  private static final String DEFAULT_ACTION = "SCAN";
  private static final String DEFAULT_DECISION = "APPROVED";

  private final ProjectApprovalService service;

  public ProjectApprovalController(ProjectApprovalService service) {
    this.service = service;
  }

  @GetMapping
  public List<ProjectApproval> list(@PathVariable Long projectId) {
    return service.list(projectId);
  }

  @PostMapping
  public ProjectApproval request(
      @PathVariable Long projectId, @RequestBody Map<String, String> body) {
    return service.request(
        projectId,
        body.getOrDefault("action", DEFAULT_ACTION),
        body.get("comment"),
        body.get("authorizationSnapshotHash"));
  }

  @PostMapping("/{approvalId}/decision")
  public ProjectApproval decide(
      @PathVariable Long projectId,
      @PathVariable Long approvalId,
      @RequestBody Map<String, String> body) {
    return service.decide(
        projectId,
        approvalId,
        body.getOrDefault("status", DEFAULT_DECISION),
        body.get("comment"));
  }
}
