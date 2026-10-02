package com.bachelor.toolbox.ai;

import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AiPlanApprovalController {
  private final AiPlanApprovalService service;
  public AiPlanApprovalController(AiPlanApprovalService service) { this.service = service; }

  @PostMapping("/api/projects/{projectId}/approvals/{approvalId}/execute")
  public AiDispatchResponse resume(@PathVariable Long projectId, @PathVariable Long approvalId) throws Exception {
    return service.resume(projectId, approvalId);
  }
}
