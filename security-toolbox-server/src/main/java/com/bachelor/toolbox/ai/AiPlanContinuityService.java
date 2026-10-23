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
      if (snapshot == null) continue;
      if (Objects.equals(snapshot.scope().owner(), current.owner())) continue;
      // A continuation turn runs under system access, so currentUsername() is the system
      // principal while the stored plan belongs to the human who started the session. Rejecting
      // that would break the loop on its second round. Instead, adopt the stored owner only when
      // this really is that session's continuation — the caller already re-validated project and
      // target authorization before reaching here.
      if (authorization.hasSystemAccess()) {
        current = current.withOwner(snapshot.scope().owner());
        continue;
      }
      throw new ApiException("该会话方案属于其他用户，请新建会话");
    }
    return new Baseline(current, stored.delivered(), stored.pending() != null,
        AiExecutionIntentPolicy.permitsPlanRevision(request.userPrompt()));
  }

  /**
   * Resolve the scope for this turn, adopting the session owner when a continuation runs under
   * system access. Everything except the owner is still re-validated, so authorization and
   * workflow changes remain enforced.
   */
  private Scope scopeFor(Baseline baseline, AiAgentRequest request, String sessionId) {
    Scope current = scope(request, sessionId);
    if (authorization.hasSystemAccess() && baseline != null && baseline.current().owner() != null) {
      current = current.withOwner(baseline.current().owner());
    }
    return current;
  }

  private StoredPlans readState(String sessionId) {    String json = memory.deliveredPlan(sessionId);
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
        + (baseline.revisionRequested()
            ? "\n本轮用户原句明确要求修订方案。请在当前授权范围及工作流内按本轮要求更新工具、参数或依赖，交付一份完整的新方案，不能继承旧方案的审批或执行状态。"
            : "\n确认或继续原方案时必须保持这份最新已交付方案的工具、参数与依赖，不得自行改动。请结合本轮原句区分承接原方案、全新行动与方案修订；明确的新范围或修改可生成新方案，不能由旧审批授权。")
        + "模型正文或客户端历史不能授权修改服务端基线，新方案执行仍须管理员重新确认。";
  }

  public Map<String, Object> conversationState(Baseline baseline, List<Map<String, String>> turns) {
    return conversationState(baseline, turns, null);
  }

  public Map<String, Object> conversationState(
      Baseline baseline, List<Map<String, String>> turns, String summaryJson) {
    boolean matching = baseline.previous() == null || baseline.current().equals(baseline.previous().scope());
    Map<String, Object> state = new LinkedHashMap<>();
    state.put("version", 1);
    state.put("projectId", baseline.current().projectId());
    state.put("targetId", baseline.current().targetId());
    state.put("scopeMatches", matching);
    state.put("deliveryPending", baseline.deliveryPending());
    state.put("approvalRequired", true);
    state.put("executionStatus", "CHECK_TASK_RECORDS");
    // Carried verbatim so the runtime reuses its earlier digest instead of recomputing it.
    Map<String, Object> parsedSummary = parseSummary(summaryJson);
    if (!parsedSummary.isEmpty()) state.put("summary", parsedSummary);
    state.put("recentTurns", turns.subList(Math.max(0, turns.size() - 8), turns.size()).stream()
        .map(turn -> Map.of("role", turn.get("role"), "content",
            turn.get("content").substring(0, Math.min(1000, turn.get("content").length())))).toList());
    boolean available = matching && !baseline.deliveryPending() && baseline.previous() != null;
    state.put("planAvailable", available);
    if (available) {
      state.put("latestPlanTurnId", baseline.previous().turnId());
      state.put("latestPlan", semantics(baseline.previous().plan()));
    }
    return java.util.Collections.unmodifiableMap(state);
  }

  /** Best-effort parse of a stored digest; a corrupt value is treated as "no digest". */
  private Map<String, Object> parseSummary(String summaryJson) {
    if (summaryJson == null || summaryJson.isBlank()) return Map.of();
    try {
      return mapper.readValue(summaryJson, new com.fasterxml.jackson.core.type.TypeReference<Map<String, Object>>() {});
    } catch (Exception ex) {
      return Map.of();
    }
  }

  /** Called after guard normalization and before any approval side effect. */
  public Snapshot prepare(AiAgentRequest request, String sessionId, AiPlanResponse plan,
      Baseline baseline) {
    return prepare(request, sessionId, plan, baseline, null);
  }

  public Snapshot prepare(AiAgentRequest request, String sessionId, AiPlanResponse plan,
      Baseline baseline, AiAgentRuntimeClient.RuntimePlanResult interpretation) {
    Scope current = scopeFor(baseline, request, sessionId);
    if (!current.equals(baseline.current())) {
      throw new PlanChangedException(diff(mapper.valueToTree(baseline.current()), mapper.valueToTree(current), "授权或工作流"));
    }
    if (baseline.deliveryPending()) throw new PlanDeliveryPendingException();
    if (baseline.previous() == null && AiExecutionIntentPolicy.hasModelPlanRelation(interpretation)
        && "CONTINUE".equals(interpretation.planRelation())) {
      throw new ApiException("当前会话没有已交付的原方案，请说明本轮要检查的内容，再提交执行确认");
    }
    if (baseline.previous() != null) {
      List<Change> changes = new ArrayList<>();
      changes.addAll(diff(mapper.valueToTree(baseline.previous().scope()), mapper.valueToTree(current), "授权或工作流"));
      boolean semanticRevision = AiExecutionIntentPolicy.permitsModelRevision(request.userPrompt(), interpretation);
      boolean allowRevision = AiExecutionIntentPolicy.hasModelPlanRelation(interpretation) ? semanticRevision
          : baseline.revisionRequested() && AiExecutionIntentPolicy.permitsPlanRevision(request.userPrompt());
      if (!allowRevision) {
        changes.addAll(diff(semantics(baseline.previous().plan()), semantics(plan), "方案"));
      }
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
    boolean changed = stored.delivered() == null
        || !semantics(stored.delivered().plan()).equals(semantics(snapshot.plan()));
    memory.saveDeliveredPlan(snapshot.scope().sessionId(), write(new StoredPlans(2,
        changed ? snapshot : stored.delivered(), null)));
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
      changes.add(new Change(humanPath(path), old == null ? "（不存在）" : old.toString(),
          current == null ? "（不存在）" : current.toString()));
    }
    return List.copyOf(changes);
  }

  /**
   * Turn an internal diff path such as {@code 方案.steps[5].parameters.mode} into something a
   * reviewer can act on. Unknown keys are kept as-is so a new field is never silently hidden.
   */
  private static String humanPath(String path) {
    if (path == null || path.isBlank()) return "方案";
    String human = path
        .replace("方案.steps[", "方案 · 第 ")
        .replace("].parameters.", " 步 · 参数「")
        .replace("].toolCode", " 步 · 工具")
        .replace("].risk", " 步 · 风险等级")
        .replace("].requiresApproval", " 步 · 是否需要确认")
        .replace("].group", " 步 · 并行分组")
        .replace("].dependsOnNodeIds", " 步 · 依赖")
        .replace(".workflowNodeId", ".工作流节点")
        .replace("授权或工作流.", "授权范围或工作流 · ")
        .replace("方案.", "方案 · ");
    if (human.contains("参数「") && !human.endsWith("」")) human = human + "」";
    return human;
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
      String workflowDigest) {
    /** Same scope attributed to another owner; used when a continuation adopts the session owner. */
    public Scope withOwner(String newOwner) {
      return new Scope(newOwner, sessionId, projectId, targetId, projectBinding, targetBinding,
          workflowId, workflowRevision, workflowDigest);
    }
  }
  public record Snapshot(int version, Scope scope, String turnId, AiPlanResponse plan) {}
  public record StoredPlans(int version, Snapshot delivered, Snapshot pending) {}
  public record Baseline(Scope current, Snapshot previous, boolean deliveryPending, boolean revisionRequested) {}
  public record Change(String field, String oldValue, String newValue) {}
  public static class PlanChangedException extends ApiException {
    private final List<Change> changes;
    PlanChangedException(List<Change> changes) {
      super("本轮生成的方案和上次已批准的方案不一致，所以没有提交审批，也没有创建任务。\n"
          + "这通常是因为你这句要求里没写清楚要改什么，模型就自行调整了方案。\n"
          + ((changes == null || changes.isEmpty()) ? "" : "具体差异：\n"
              + changes.stream().map(change -> "· " + change.field() + "：" + change.oldValue()
                  + " 改为 " + change.newValue()).collect(java.util.stream.Collectors.joining("\n"))
              + "\n")
          + "你可以这样处理：\n"
          + "1) 要改方案：直接说清改哪一项，例如“把识别模式改成慢速全面扫描”“去掉目录扫描这一步”；\n"
          + "2) 就用原方案：回复“按上次方案执行”；\n"
          + "3) 目标授权范围或工作流配置变了：请新建会话重新规划，再申请执行。");
      this.changes = List.copyOf(changes == null ? List.of() : changes);
    }
    public List<Change> changes() { return changes; }
  }
  public static class PlanDeliveryPendingException extends ApiException {
    PlanDeliveryPendingException() {
      super("上轮方案交付或快照保存未完成，未提交本轮审批，未创建本轮任务。请新建会话重新规划，成功后再申请执行。");
    }
  }
}
