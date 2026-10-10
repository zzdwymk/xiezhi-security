package com.bachelor.toolbox.ai;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.project.AssessmentProjectService;
import com.bachelor.toolbox.project.ProjectAuthorizationService;
import com.bachelor.toolbox.target.TargetService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import java.util.TreeSet;
import org.springframework.stereotype.Service;

/** Keeps a server-owned execution baseline. Model text and client history never update it. */
@Service
public class AiPlanContinuityService {
  private final AiConversationMemoryService memory;
  private final ProjectAuthorizationService authorization;
  private final AssessmentProjectService projects;
  private final TargetService targets;
  private final AgentWorkflowSpecService workflows;
  private final ObjectMapper mapper;

  public AiPlanContinuityService(AiConversationMemoryService memory,
      ProjectAuthorizationService authorization, AssessmentProjectService projects,
      TargetService targets, AgentWorkflowSpecService workflows, ObjectMapper mapper) {
    this.memory = memory;
    this.authorization = authorization;
    this.projects = projects;
    this.targets = targets;
    this.workflows = workflows;
    this.mapper = mapper;
  }

  public Baseline open(AiAgentRequest request, String sessionId) {
    Scope current = scope(request, sessionId);
    StoredPlans stored = readState(sessionId);
    for (Snapshot snapshot : new Snapshot[] {stored.delivered(), stored.pending()}) {
      if (snapshot != null && !Objects.equals(snapshot.scope().owner(), current.owner())) {
        throw new ApiException("该会话方案属于其他用户，请新建会话");
      }
    }
    return new Baseline(current, stored.delivered(), stored.pending() != null);
  }

  private StoredPlans readState(String sessionId) {
    String json = memory.deliveredPlan(sessionId);
    StoredPlans stored = new StoredPlans(2, null, null);
    if (json != null && !json.isBlank()) {
      try {
        int version = mapper.readTree(json).path("version").asInt();
        if (version == 1) stored = new StoredPlans(2, mapper.readValue(json, Snapshot.class), null);
        else if (version == 2) stored = mapper.readValue(json, StoredPlans.class);
        else throw new IllegalArgumentException("unknown snapshot version");
        for (Snapshot snapshot : new Snapshot[] {stored.delivered(), stored.pending()}) {
          if (snapshot != null && (snapshot.version() != 1 || snapshot.scope() == null || snapshot.plan() == null
              || snapshot.plan().steps() == null || snapshot.plan().steps().isEmpty())) {
            throw new IllegalArgumentException("invalid snapshot");
          }
        }
      } catch (Exception ex) {
        // A malformed new snapshot is not an empty legacy snapshot: never silently permit execution.
        throw new ApiException("上次方案快照不可读取，已保留原会话数据；请新建会话重新规划");
      }
    }
    return stored;
  }

  public String plannerContext(Baseline baseline) {
    if (baseline.deliveryPending()) {
      return "\n\n上轮方案交付或快照保存未完成，请新建会话重新规划；当前会话不能再提交工具方案或申请执行，未完成候选不作为历史方案。";
    }
    if (baseline.previous() == null) return "";
    if (!baseline.current().equals(baseline.previous().scope())) {
      return "\n\n服务端记录的上次方案授权范围或工作流已变化，不能沿用执行，请新建会话重新规划。";
    }
    return "\n\n服务端已验证且已成功交付的上次结构化方案（不是执行授权）：\n"
        + write(semantics(baseline.previous().plan()))
        + "\n当前会话首份已交付方案的执行语义固定；需要改变工具、参数或依赖时请新建会话重新规划。"
        + "模型正文或客户端历史不能修改这份服务端基线，执行仍须管理员确认。";
  }

  /** Called after guard normalization and before any approval side effect. */
  public Snapshot prepare(AiAgentRequest request, String sessionId, AiPlanResponse plan,
      Baseline baseline) {
    Scope current = scope(request, sessionId);
    if (!current.equals(baseline.current())) {
      throw new PlanChangedException(diff(mapper.valueToTree(baseline.current()), mapper.valueToTree(current), "授权或工作流"));
    }
    if (baseline.deliveryPending()) throw new PlanDeliveryPendingException();
    if (baseline.previous() != null) {
      List<Change> changes = new ArrayList<>();
      changes.addAll(diff(mapper.valueToTree(baseline.previous().scope()), mapper.valueToTree(current), "授权或工作流"));
      changes.addAll(diff(semantics(baseline.previous().plan()), semantics(plan), "方案"));
      if (!changes.isEmpty()) throw new PlanChangedException(changes);
    }
    if (request.executionRequested()) {
      projects.validateProjectTarget(request.projectId(), request.targetId());
      targets.getCurrentlyAuthorized(request.targetId());
    }
    // Round-trip now: serialization errors must happen before approvals or completion delivery.
    try {
      return mapper.readValue(write(new Snapshot(1, current, request.turnId(), plan)), Snapshot.class);
    } catch (Exception ex) {
      throw new ApiException("无法保存本轮方案快照，未提交执行确认，请重试");
    }
  }

  /** Call only after SUCCESS audit and the done sink returned successfully (not a UI render ACK). */
  public void delivered(Snapshot snapshot) {
    var stored = readState(snapshot.scope().sessionId());
    if (!snapshot.equals(stored.pending())) throw new ApiException("本轮待交付方案标识不一致，已停止晋升方案基线");
    memory.saveDeliveredPlan(snapshot.scope().sessionId(), write(new StoredPlans(2,
        stored.delivered() == null ? snapshot : stored.delivered(), null)));
  }

  /** Durable write before approvals/done. Failed delivery remains pending and blocks future EXECUTE. */
  public void stage(Snapshot snapshot) {
    var stored = readState(snapshot.scope().sessionId());
    memory.saveDeliveredPlan(snapshot.scope().sessionId(), write(new StoredPlans(2, stored.delivered(), snapshot)));
  }

  private Scope scope(AiAgentRequest request, String sessionId) {
    String owner = authorization.currentUsername();
    var project = authorization.requireAccess(request.projectId());
    projects.validateProjectTargetMembership(request.projectId(), request.targetId());
    var target = targets.get(request.targetId());
    var workflow = workflows.freezeSnapshot(request.projectId(), request.workflowId(),
        request.workflowRevision(), request.workflowDigest());
    return new Scope(owner, sessionId, request.projectId(), request.targetId(),
        AiPlanApprovalService.projectBinding(project), AiPlanApprovalService.targetBinding(target),
        workflow.workflowId(), workflow.revision(), workflow.specDigest());
  }

  static JsonNode semantics(AiPlanResponse plan) {
    ObjectMapper mapper = new ObjectMapper();
    List<Map<String, Object>> steps = new ArrayList<>();
    for (var step : plan.steps()) {
      Map<String, Object> item = new LinkedHashMap<>();
      item.put("toolCode", step.toolCode());
      item.put("workflowNodeId", step.workflowNodeId());
      item.put("group", step.group());
      item.put("dependsOnNodeIds", new TreeSet<>(step.dependsOnNodeIds()));
      item.put("risk", step.risk());
      item.put("requiresApproval", step.requiresApproval());
      item.put("parameters", normalize(step.parameters()));
      steps.add(item);
    }
    return mapper.valueToTree(Map.of("steps", steps));
  }

  private static Object normalize(Object value) {
    if (value instanceof Map<?, ?> map) {
      Map<String, Object> sorted = new TreeMap<>();
      map.forEach((key, item) -> sorted.put(key.toString(), normalize(item)));
      return sorted;
    }
    if (value instanceof List<?> list) return list.stream().map(AiPlanContinuityService::normalize).toList();
    if (value instanceof Number number) return new java.math.BigDecimal(number.toString()).stripTrailingZeros();
    return value;
  }

  private static List<Change> diff(JsonNode old, JsonNode current, String path) {
    if (Objects.equals(old, current)) return List.of();
    List<Change> changes = new ArrayList<>();
    if (old != null && current != null && old.isObject() && current.isObject()) {
      TreeSet<String> keys = new TreeSet<>();
      old.fieldNames().forEachRemaining(keys::add);
      current.fieldNames().forEachRemaining(keys::add);
      keys.forEach(key -> changes.addAll(diff(old.get(key), current.get(key), path + "." + key)));
    } else if (old != null && current != null && old.isArray() && current.isArray()) {
      for (int index = 0; index < Math.max(old.size(), current.size()); index++) {
        changes.addAll(diff(old.get(index), current.get(index), path + "[" + (index + 1) + "]"));
      }
    } else {
      changes.add(new Change(path, old == null ? "（不存在）" : old.toString(),
          current == null ? "（不存在）" : current.toString()));
    }
    return List.copyOf(changes);
  }

  private String write(Object value) {
    try {
      return mapper.writeValueAsString(value);
    } catch (Exception ex) {
      throw new ApiException("方案快照暂时不可写");
    }
  }

  public record Scope(String owner, String sessionId, Long projectId, Long targetId,
      String projectBinding, String targetBinding, String workflowId, Long workflowRevision,
      String workflowDigest) {}
  public record Snapshot(int version, Scope scope, String turnId, AiPlanResponse plan) {}
  public record StoredPlans(int version, Snapshot delivered, Snapshot pending) {}
  public record Baseline(Scope current, Snapshot previous, boolean deliveryPending) {}
  public record Change(String field, String oldValue, String newValue) {}
  public static class PlanChangedException extends ApiException {
    private final List<Change> changes;
    PlanChangedException(List<Change> changes) {
      super("本轮方案与上次已交付方案不同，未提交审批，未创建任务。请新建会话重新规划，再申请执行。变化：\n"
          + changes.stream().map(change -> change.field() + "：原值 " + change.oldValue()
              + " → 新值 " + change.newValue()).collect(java.util.stream.Collectors.joining("\n")));
      this.changes = List.copyOf(changes);
    }
    public List<Change> changes() { return changes; }
  }
  public static class PlanDeliveryPendingException extends ApiException {
    PlanDeliveryPendingException() {
      super("上轮方案交付或快照保存未完成，未提交本轮审批，未创建本轮任务。请新建会话重新规划，成功后再申请执行。");
    }
  }
}
