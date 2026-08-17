package com.bachelor.toolbox.ai;

import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.project.AssessmentProjectService;
import com.bachelor.toolbox.target.TargetService;
import com.bachelor.toolbox.task.SecurityTask;
import com.bachelor.toolbox.task.SecurityTaskRepository;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Internal outbox for safe, read-only cross-turn Agent continuation. */
@Service
public class CrossTurnRecoveryService {
  private static final Set<String> TERMINAL_TASKS =
      Set.of("SUCCESS", "FAILED", "TIMEOUT", "REJECTED", "CANCELLED", "SKIPPED");
  private static final Set<String> CLAIMABLE =
      Set.of(ConversationTombstone.WAITING_TASKS, ConversationTombstone.FAILED);
  private static final int MAX_TASKS = 20;
  private static final int MAX_ATTEMPTS = 3;

  private final ConversationTombstoneRepository tombstones;
  private final AgentLedgerService ledger;
  private final AssessmentProjectService projects;
  private final TargetService targets;
  private final AgentWorkflowSpecService workflows;
  private final SecurityTaskRepository tasks;
  private final ObjectMapper objectMapper;
  private final AuditService audit;
  private final Duration recoveryWindow;
  private final Duration processingLease;

  public CrossTurnRecoveryService(
      ConversationTombstoneRepository tombstones,
      AgentLedgerService ledger,
      AssessmentProjectService projects,
      TargetService targets,
      AgentWorkflowSpecService workflows,
      SecurityTaskRepository tasks,
      ObjectMapper objectMapper,
      AuditService audit,
      @Value("${toolbox.ai.ledger.recovery-window-seconds:900}") long recoveryWindowSeconds,
      @Value("${toolbox.ai.ledger.recovery-processing-lease-seconds:300}")
          long processingLeaseSeconds) {
    this.tombstones = tombstones;
    this.ledger = ledger;
    this.projects = projects;
    this.targets = targets;
    this.workflows = workflows;
    this.tasks = tasks;
    this.objectMapper = objectMapper;
    this.audit = audit;
    this.recoveryWindow = Duration.ofSeconds(Math.max(60, Math.min(recoveryWindowSeconds, 86_400)));
    this.processingLease =
        Duration.ofSeconds(Math.max(30, Math.min(processingLeaseSeconds, 3_600)));
  }

  /** Persist only after Java has accepted the complete runtime Ledger chain and created tasks. */
  @Transactional
  public void checkpoint(CheckpointRequest request) {
    requireRequest(request);
    projects.validateProjectTargetMembership(request.projectId(), request.targetId());
    targets.getCurrentlyAuthorized(request.targetId(), request.projectId());
    AgentLedgerService.StateSnapshot state = ledger.state(request.projectId(), request.runId(), request.nodeRunId());
    if (!state.found() || !state.valid() || !state.terminal()) {
      throw new ApiException("Agent Ledger 尚未形成可续接的终态锚点");
    }
    if (!Objects.equals(state.workflowDigest(), request.workflowDigest())
        || state.workflowRevision() != request.workflowRevision()
        || !Objects.equals(state.policyRevision(), request.policyRevision())
        || state.lastSequence() != request.ledgerSequence()
        || !Objects.equals(state.headDigest(), request.ledgerHeadDigest())) {
      throw new ApiException("Agent Ledger 续接锚点与当前请求不一致");
    }
    List<Long> taskIds = normalizeTaskIds(request.pendingTaskIds());
    List<SecurityTask> persisted = tasks.findAllById(taskIds);
    if (persisted.size() != taskIds.size()
        || persisted.stream()
            .anyMatch(
                task ->
                    !Objects.equals(task.getProjectId(), request.projectId())
                        || !Objects.equals(task.getTargetId(), request.targetId()))) {
      throw new ApiException("Agent 续接任务越过项目或目标边界");
    }
    String taskJson = write(taskIds);
    String requestDigest = requestDigest(request, taskIds);
    Optional<ConversationTombstone> byRuntimeNode =
        tombstones.findByRunIdAndNodeRunId(request.runId(), request.nodeRunId());
    ConversationTombstone existing =
        byRuntimeNode == null ? null : byRuntimeNode.orElse(null);
    if (existing == null) {
      Optional<ConversationTombstone> byTurn =
          tombstones.findByProjectIdAndTargetIdAndTurnIdAndWorkflowDigest(
              request.projectId(),
              request.targetId(),
              request.turnId(),
              request.workflowDigest());
      existing = byTurn == null ? null : byTurn.orElse(null);
    }
    if (existing != null) {
      if (!sameCheckpoint(existing, request, taskJson)) {
        throw new ApiException("相同 Agent 运行不能写入不同的续接任务");
      }
      // A replay is intentionally side-effect free. The worker owns Python checkpoint delivery
      // and will retry it using the already committed Java outbox row.
      return;
    }
    ConversationTombstone tombstone = new ConversationTombstone();
    tombstone.setProjectId(request.projectId());
    tombstone.setTargetId(request.targetId());
    tombstone.setRunId(request.runId());
    tombstone.setNodeRunId(request.nodeRunId());
    tombstone.setSessionId(request.sessionId());
    tombstone.setTurnId(request.turnId());
    tombstone.setWorkflowId(request.workflowId());
    tombstone.setWorkflowRevision(request.workflowRevision());
    tombstone.setWorkflowDigest(request.workflowDigest());
    tombstone.setOuterNodeId(request.outerNodeId());
    tombstone.setPolicyRevision(request.policyRevision());
    tombstone.setLedgerSequence(request.ledgerSequence());
    tombstone.setLedgerHeadDigest(request.ledgerHeadDigest());
    tombstone.setRequestDigest(requestDigest);
    tombstone.setPendingTaskIdsJson(taskJson);
    tombstone.setStatus(ConversationTombstone.WAITING_TASKS);
    tombstone.setNextAttemptAt(Instant.now());
    tombstones.save(tombstone);
    audit.record(
        "AGENT_CONTINUATION_CHECKPOINT",
        "PROJECT",
        request.projectId(),
        "runId=" + request.runId() + ";taskIds=" + taskJson,
        "WAITING_TASKS");
  }

  public List<Long> candidateIds() {
    Instant now = Instant.now();
    return tombstones
        .findTop100ByStatusInAndNextAttemptAtLessThanEqualOrderByCreatedAtAsc(
            List.of(
                ConversationTombstone.WAITING_TASKS,
                ConversationTombstone.FAILED,
                ConversationTombstone.PROCESSING),
            now)
        .stream()
        .map(ConversationTombstone::getId)
        .toList();
  }

  /** Claim one candidate only when every task is terminal and all authority anchors still match. */
  @Transactional
  public ContinuationClaim claim(Long id) {
    ConversationTombstone tombstone =
        tombstones.findLockedById(id).orElseThrow(() -> new ApiException("续接记录不存在"));
    Instant now = Instant.now();
    boolean staleProcessing =
        ConversationTombstone.PROCESSING.equals(tombstone.getStatus())
            && tombstone.getProcessingStartedAt() != null
            && tombstone.getProcessingStartedAt().isBefore(now.minus(processingLease));
    if (!CLAIMABLE.contains(tombstone.getStatus()) && !staleProcessing) return null;
    if (tombstone.getNextAttemptAt() != null && tombstone.getNextAttemptAt().isAfter(now)) return null;
    if (tombstone.getCreatedAt().isBefore(now.minus(recoveryWindow))) {
      stale(tombstone, "RECOVERY_WINDOW_EXPIRED");
      return null;
    }
    List<Long> taskIds = parseTaskIds(tombstone.getPendingTaskIdsJson());
    List<SecurityTask> taskRows = tasks.findAllById(taskIds);
    if (taskRows.size() != taskIds.size()) {
      stale(tombstone, "TASK_NOT_FOUND");
      return null;
    }
    if (taskRows.stream().anyMatch(task -> !TERMINAL_TASKS.contains(task.getStatus()))) return null;

    tombstone.setAttempt(tombstone.getAttempt() + 1);
    try {
      projects.validateProjectTarget(tombstone.getProjectId(), tombstone.getTargetId());
      targets.getCurrentlyAuthorized(tombstone.getTargetId(), tombstone.getProjectId());
      AgentWorkflowSpecService.WorkflowSnapshot snapshot =
          workflows.freezeSnapshot(tombstone.getProjectId());
      if (!Objects.equals(snapshot.workflowId(), tombstone.getWorkflowId())
          || !Objects.equals(snapshot.revision(), tombstone.getWorkflowRevision())
          || !Objects.equals(snapshot.specDigest(), tombstone.getWorkflowDigest())) {
        stale(tombstone, "STALE_WORKFLOW");
        return null;
      }
      if (!Objects.equals(tombstone.getPolicyRevision(), AiAgentRuntimeClient.POLICY_REVISION)) {
        stale(tombstone, "STALE_POLICY");
        return null;
      }
      AgentLedgerService.StateSnapshot state =
          ledger.state(tombstone.getProjectId(), tombstone.getRunId(), tombstone.getNodeRunId());
      if (!state.found()
          || !state.valid()
          || !state.terminal()
          || state.lastSequence() != tombstone.getLedgerSequence()
          || !Objects.equals(state.headDigest(), tombstone.getLedgerHeadDigest())
          || !Objects.equals(state.workflowDigest(), tombstone.getWorkflowDigest())
          || !Objects.equals(state.policyRevision(), tombstone.getPolicyRevision())) {
        stale(tombstone, "STALE_LEDGER");
        return null;
      }
      tombstone.setStatus(ConversationTombstone.PROCESSING);
      tombstone.setProcessingStartedAt(now);
      tombstone.setNextAttemptAt(now.plus(processingLease));
      tombstone.setLastError(null);
      tombstones.save(tombstone);
      return new ContinuationClaim(
          tombstone.getId(),
          tombstone.getProjectId(),
          tombstone.getTargetId(),
          tombstone.getRunId(),
          tombstone.getNodeRunId(),
          tombstone.getSessionId(),
          tombstone.getTurnId(),
          tombstone.getWorkflowId(),
          tombstone.getWorkflowRevision(),
          tombstone.getWorkflowDigest(),
          tombstone.getOuterNodeId(),
          tombstone.getPolicyRevision(),
          tombstone.getLedgerSequence(),
          tombstone.getLedgerHeadDigest(),
          tombstone.getRequestDigest(),
          taskIds,
          tombstone.getAttempt(),
          snapshot);
    } catch (RuntimeException ex) {
      retryOrFail(tombstone, safeMessage(ex));
      return null;
    }
  }

  @Transactional
  public void markContinued(Long id) {
    tombstones.findLockedById(id).ifPresent(tombstone -> {
      if (ConversationTombstone.CONTINUED.equals(tombstone.getStatus())) return;
      tombstone.setStatus(ConversationTombstone.CONTINUED);
      tombstone.setContinuedAt(Instant.now());
      tombstone.setProcessingStartedAt(null);
      tombstone.setNextAttemptAt(null);
      tombstone.setLastError(null);
      tombstones.save(tombstone);
      audit.record("AGENT_CONTINUATION_COMPLETED", "PROJECT", tombstone.getProjectId(),
          "runId=" + tombstone.getRunId(), "CONTINUED");
    });
  }

  /** Close an in-doubt execution without retrying a model call whose outcome is unknown. */
  @Transactional
  public void markSkipped(Long id, String reason) {
    tombstones.findLockedById(id).ifPresent(tombstone -> {
      if (ConversationTombstone.CONTINUED.equals(tombstone.getStatus())
          || ConversationTombstone.SKIPPED.equals(tombstone.getStatus())) return;
      tombstone.setStatus(ConversationTombstone.SKIPPED);
      tombstone.setContinuedAt(Instant.now());
      tombstone.setProcessingStartedAt(null);
      tombstone.setNextAttemptAt(null);
      tombstone.setLastError(safeMessage(reason));
      tombstones.save(tombstone);
      audit.record(
          "AGENT_CONTINUATION_SKIPPED",
          "PROJECT",
          tombstone.getProjectId(),
          "runId=" + tombstone.getRunId() + ";reason=" + safeMessage(reason),
          "SKIPPED");
    });
  }

  @Transactional
  public void markFailure(Long id, String error) {
    tombstones.findLockedById(id).ifPresent(tombstone -> retryOrFail(tombstone, error));
  }

  private void retryOrFail(ConversationTombstone tombstone, String error) {
    tombstone.setLastError(safeMessage(error));
    tombstone.setProcessingStartedAt(null);
    if (tombstone.getAttempt() >= MAX_ATTEMPTS) {
      tombstone.setStatus(ConversationTombstone.FAILED);
      tombstone.setNextAttemptAt(null);
    } else {
      tombstone.setStatus(ConversationTombstone.WAITING_TASKS);
      tombstone.setNextAttemptAt(Instant.now().plusSeconds(15L * tombstone.getAttempt()));
    }
    tombstones.save(tombstone);
  }

  private void stale(ConversationTombstone tombstone, String reason) {
    tombstone.setStatus(ConversationTombstone.STALE);
    tombstone.setProcessingStartedAt(null);
    tombstone.setNextAttemptAt(null);
    tombstone.setLastError(reason);
    tombstones.save(tombstone);
    audit.record("AGENT_CONTINUATION_REJECTED", "PROJECT", tombstone.getProjectId(),
        "runId=" + tombstone.getRunId() + ";reason=" + reason, "STALE");
  }

  private boolean sameCheckpoint(
      ConversationTombstone existing, CheckpointRequest request, String taskJson) {
    return Objects.equals(existing.getProjectId(), request.projectId())
        && Objects.equals(existing.getTargetId(), request.targetId())
        && Objects.equals(existing.getSessionId(), request.sessionId())
        && Objects.equals(existing.getTurnId(), request.turnId())
        && Objects.equals(existing.getWorkflowId(), request.workflowId())
        && existing.getWorkflowRevision() == request.workflowRevision()
        && Objects.equals(existing.getWorkflowDigest(), request.workflowDigest())
        && Objects.equals(existing.getOuterNodeId(), request.outerNodeId())
        && Objects.equals(existing.getPolicyRevision(), request.policyRevision())
        && existing.getLedgerSequence() == request.ledgerSequence()
        && Objects.equals(existing.getLedgerHeadDigest(), request.ledgerHeadDigest())
        && Objects.equals(existing.getRequestDigest(), requestDigest(request, request.pendingTaskIds()))
        && Objects.equals(existing.getPendingTaskIdsJson(), taskJson);
  }

  Map<String, Object> checkpointBody(ContinuationClaim claim) {
    return checkpointBody(
        claim.projectId(),
        claim.targetId(),
        claim.sessionId(),
        claim.runId(),
        claim.nodeRunId(),
        claim.workflowId(),
        claim.workflowRevision(),
        claim.workflowDigest(),
        claim.outerNodeId(),
        claim.policyRevision(),
        claim.requestDigest(),
        claim.ledgerSequence(),
        claim.ledgerHeadDigest(),
        claim.taskIds());
  }

  private Map<String, Object> checkpointBody(
      Long projectId,
      Long targetId,
      String sessionId,
      String runId,
      String nodeRunId,
      String workflowId,
      long workflowRevision,
      String workflowDigest,
      String outerNodeId,
      String policyRevision,
      String requestDigest,
      long ledgerSequence,
      String ledgerHeadDigest,
      List<Long> taskIds) {
    Map<String, Object> body = new java.util.LinkedHashMap<>();
    body.put("projectId", projectId);
    body.put("targetId", targetId);
    body.put("conversationId", sessionId);
    body.put("runId", runId);
    body.put("nodeRunId", nodeRunId);
    body.put("workflowId", workflowId);
    body.put("workflowRevision", workflowRevision);
    body.put("workflowDigest", workflowDigest);
    body.put("outerNodeId", outerNodeId);
    body.put("policyRevision", policyRevision);
    body.put("requestDigest", requestDigest);
    body.put("stateVersion", ledgerSequence);
    body.put("ledgerDigest", ledgerHeadDigest);
    body.put("pendingTaskIds", taskIds);
    return body;
  }

  private String requestDigest(CheckpointRequest request, List<Long> taskIds) {
    Map<String, Object> values = new java.util.TreeMap<>();
    values.put("projectId", request.projectId());
    values.put("targetId", request.targetId());
    values.put("conversationId", request.sessionId());
    values.put("workflowId", request.workflowId());
    values.put("workflowRevision", request.workflowRevision());
    values.put("workflowDigest", request.workflowDigest());
    values.put("outerNodeId", request.outerNodeId());
    values.put("policyRevision", request.policyRevision());
    values.put("stateVersion", request.ledgerSequence());
    values.put("ledgerDigest", request.ledgerHeadDigest());
    values.put("pendingTaskIds", taskIds.stream().sorted().toList());
    try {
      byte[] payload = objectMapper.writeValueAsBytes(values);
      return "sha256:"
          + java.util.HexFormat.of()
              .formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(payload));
    } catch (Exception ex) {
      throw new ApiException("Agent 续接请求摘要失败");
    }
  }

  private void requireRequest(CheckpointRequest request) {
    if (request == null
        || request.projectId() == null
        || request.targetId() == null
        || blank(request.runId())
        || blank(request.nodeRunId())
        || blank(request.sessionId())
        || blank(request.turnId())
        || blank(request.workflowId())
        || request.workflowRevision() <= 0
        || !digest(request.workflowDigest())
        || blank(request.outerNodeId())
        || blank(request.policyRevision())
        || request.ledgerSequence() <= 0
        || !digest(request.ledgerHeadDigest())) {
      throw new ApiException("Agent 续接锚点不完整");
    }
  }

  private List<Long> normalizeTaskIds(List<Long> ids) {
    if (ids == null || ids.isEmpty() || ids.size() > MAX_TASKS) {
      throw new ApiException("Agent 续接任务数量无效");
    }
    List<Long> normalized = ids.stream().filter(Objects::nonNull).distinct().sorted().toList();
    if (normalized.size() != ids.size() || normalized.stream().anyMatch(id -> id <= 0)) {
      throw new ApiException("Agent 续接任务 ID 无效");
    }
    return normalized;
  }

  private List<Long> parseTaskIds(String value) {
    try {
      return normalizeTaskIds(objectMapper.readValue(value, new TypeReference<List<Long>>() {}));
    } catch (Exception ex) {
      throw new ApiException("Agent 续接任务清单损坏");
    }
  }

  private String write(Collection<Long> values) {
    try {
      return objectMapper.writeValueAsString(values.stream().sorted().toList());
    } catch (Exception ex) {
      throw new ApiException("Agent 续接任务清单无法保存");
    }
  }

  private boolean digest(String value) {
    return value != null && value.matches("sha256:[0-9a-f]{64}");
  }

  private boolean blank(String value) {
    return value == null || value.isBlank();
  }

  private String safeMessage(Throwable error) {
    String value = error == null ? "UNKNOWN" : Objects.toString(error.getMessage(), error.getClass().getSimpleName());
    return value.length() <= 500 ? value : value.substring(0, 500);
  }

  private String safeMessage(String error) {
    String value = Objects.toString(error, "UNKNOWN");
    return value.length() <= 500 ? value : value.substring(0, 500);
  }

  /**
   * Immutable runtime/Ledger facts known before task identifiers are allocated. Binding the
   * anchor inside the task-dispatch transaction keeps task creation and the Java continuation
   * outbox atomic without exposing a Python network call on the transaction path.
   */
  public record RecoveryAnchor(
      String runId,
      String sessionId,
      String policyRevision,
      long ledgerSequence,
      String ledgerHeadDigest) {
    public CheckpointRequest bind(AiAgentRequest request, List<Long> pendingTaskIds) {
      if (request == null) throw new ApiException("Agent 续接请求不能为空");
      return new CheckpointRequest(
          request.projectId(),
          request.targetId(),
          runId,
          request.nodeRunId(),
          sessionId,
          request.turnId(),
          request.workflowId(),
          request.workflowRevision() == null ? 0 : request.workflowRevision(),
          request.workflowDigest(),
          request.outerNodeId(),
          policyRevision,
          ledgerSequence,
          ledgerHeadDigest,
          pendingTaskIds);
    }
  }

  public record CheckpointRequest(
      Long projectId,
      Long targetId,
      String runId,
      String nodeRunId,
      String sessionId,
      String turnId,
      String workflowId,
      long workflowRevision,
      String workflowDigest,
      String outerNodeId,
      String policyRevision,
      long ledgerSequence,
      String ledgerHeadDigest,
      List<Long> pendingTaskIds) {}

  public record ContinuationClaim(
      Long tombstoneId,
      Long projectId,
      Long targetId,
      String runId,
      String nodeRunId,
      String sessionId,
      String turnId,
      String workflowId,
      long workflowRevision,
      String workflowDigest,
      String outerNodeId,
      String policyRevision,
      long ledgerSequence,
      String ledgerHeadDigest,
      String requestDigest,
      List<Long> taskIds,
      int attempt,
      AgentWorkflowSpecService.WorkflowSnapshot workflowSnapshot) {}
}
