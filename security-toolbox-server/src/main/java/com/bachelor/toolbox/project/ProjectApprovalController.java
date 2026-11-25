package com.bachelor.toolbox.project;

import com.bachelor.toolbox.common.ApiException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
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
    List<Map<String, Object>> stepOverrides = parseStepOverrides(body.get("stepOverrides"), status);
    return stepOverrides == null
        ? service.decide(projectId, approvalId, status, comment)
        : service.decide(projectId, approvalId, status, comment, stepOverrides);
  }

  /**
   * 审批弹窗提交的是“按步骤顺序排列的参数覆盖数组”。控制器必须把它原样交给
   * {@link ProjectApprovalService} 的五参 decide；否则 UI 中看到的微调会被静默丢弃，
   * 实际执行的仍是旧方案（审批内容与执行内容不一致）。
   */
  private List<Map<String, Object>> parseStepOverrides(Object raw, String status) {
    if (raw == null) return null;
    if (!"APPROVED".equals(status)) {
      throw new ApiException("仅批准方案时允许提交参数覆盖");
    }
    if (!(raw instanceof List<?> values)) {
      throw new ApiException("stepOverrides 必须是数组");
    }
    if (values.size() > 128) {
      throw new ApiException("stepOverrides 步骤数量过多");
    }
    List<Map<String, Object>> normalized = new ArrayList<>(values.size());
    for (Object value : values) {
      if (value == null) {
        normalized.add(null);
        continue;
      }
      if (!(value instanceof Map<?, ?> map)) {
        throw new ApiException("stepOverrides 每个元素必须是对象");
      }
      Map<String, Object> step = new LinkedHashMap<>();
      for (Map.Entry<?, ?> entry : map.entrySet()) {
        if (!(entry.getKey() instanceof String key) || key.isBlank()) {
          throw new ApiException("stepOverrides 参数名必须是非空字符串");
        }
        step.put(key, entry.getValue());
      }
      normalized.add(step);
    }
    return List.copyOf(normalized);
  }
}
