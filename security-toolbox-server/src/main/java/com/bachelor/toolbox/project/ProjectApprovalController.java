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

  @GetMapping("/{approvalId}/plan")
  public ProjectApprovalService.PlanDetail plan(@PathVariable Long projectId, @PathVariable Long approvalId) {
    return service.planDetail(projectId, approvalId);
  }

  @PostMapping
  public ProjectApproval request(
      @PathVariable Long projectId, @RequestBody Map<String, String> body) {
    // An absent key means "use the documented default". An explicitly present null is a
    // client-chosen value and is passed through unchanged, so the service (not the controller)
    // decides whether it is acceptable. Collapsing the two would silently turn a malformed
    // request into a broad SCAN request.
    String action = body.containsKey("action") ? body.get("action") : DEFAULT_ACTION;
    return service.request(
        projectId,
        action,
        body.get("comment"),
        body.get("authorizationSnapshotHash"));
  }

  @PostMapping("/{approvalId}/decision")
  public ProjectApproval decide(
      @PathVariable Long projectId,
      @PathVariable Long approvalId,
      @RequestBody Map<String, ?> body) {
    String comment = body.get("comment") != null ? String.valueOf(body.get("comment")) : null;
    // Same rule: only a missing status defaults to APPROVED. An explicit null must reach the
    // service and be rejected there — defaulting it would approve a plan the caller never
    // explicitly approved. The service validates the status value.
    Object rawStatus = body.containsKey("status") ? body.get("status") : DEFAULT_DECISION;
    String status = rawStatus == null ? null : String.valueOf(rawStatus);
    return service.decide(projectId, approvalId, status, comment);
  }
}
