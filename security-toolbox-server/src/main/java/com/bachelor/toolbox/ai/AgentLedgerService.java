package com.bachelor.toolbox.ai;

import com.bachelor.toolbox.common.ApiException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.regex.Pattern;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

/** Java-authoritative append and verification boundary for the finite Agent ledger. */
@Service
public class AgentLedgerService {
  public static final String LEDGER_REVISION = "java-ledger-v1";
  public static final String CORRECTION_EVENT_TYPE = "AUDIT_CORRECTION";
  public static final String CORRECTION_STATUS = "CORRECTED";

  private static final int MAX_REFERENCES = 40;
  private static final Pattern SAFE_ID = Pattern.compile("[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}");
  private static final Pattern SHA256 = Pattern.compile("sha256:[0-9a-f]{64}");
  private static final Set<String> TERMINAL_STATUSES =
      Set.of(
          "COMPLETED",
          "CLARIFY",
          "DENIED",
          "APPROVAL_REQUIRED",
          "FAILED",
          "STALE_WORKFLOW");

  private final AgentLedgerRecordRepository repository;
  private final ObjectMapper canonicalMapper;
  private final TransactionTemplate transaction;
  private final Object[] appendLocks = new Object[64];

  public AgentLedgerService(
      AgentLedgerRecordRepository repository,
      ObjectMapper objectMapper,
      PlatformTransactionManager transactionManager) {
    this.repository = repository;
    this.canonicalMapper = objectMapper.copy();
    this.canonicalMapper.enable(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS);
    this.transaction = new TransactionTemplate(transactionManager);
    for (int index = 0; index < appendLocks.length; index++) appendLocks[index] = new Object();
  }

  public AgentLedgerRecord append(AppendRequest rawRequest) {
    return append(rawRequest, false);
  }

  public AgentLedgerRecord appendCorrection(AppendRequest rawRequest) {
    return append(rawRequest, true);
  }

  /**
   * Atomically appends one already-validated runtime stream. Every item must belong to the same
   * node chain and input sequences must be contiguous. An idempotent replay may mix existing
   * entries followed by new entries; any conflicting or invalid item rolls back the whole batch.
   */
  public List<AgentLedgerRecord> appendBatch(List<AppendRequest> rawRequests) {
    if (rawRequests == null || rawRequests.isEmpty()) {
      throw new ApiException("Ledger 批次不能为空");
    }
    List<AppendRequest> requests = rawRequests.stream().map(this::normalize).toList();
    AppendRequest first = requests.get(0);
    long expectedSequence = first.sequence();
    for (AppendRequest request : requests) {
      if (!Objects.equals(first.runId(), request.runId())
          || !Objects.equals(first.nodeRunId(), request.nodeRunId())) {
        throw new ApiException("Ledger 批次只能包含同一个 nodeRun");
      }
      if (request.sequence() != expectedSequence++) {
        throw new ApiException("Ledger 批次 sequence 必须严格连续");
      }
      if (CORRECTION_EVENT_TYPE.equals(request.eventType())
          || CORRECTION_STATUS.equals(request.status())) {
        throw new ApiException("审计修正不能通过普通批次追加");
      }
    }
    Object lock = appendLocks[Math.floorMod(chainKey(first).hashCode(), appendLocks.length)];
    synchronized (lock) {
      List<AgentLedgerRecord> result =
          transaction.execute(
              ignored -> {
                List<AgentLedgerRecord> appended = new ArrayList<>(requests.size());
                for (AppendRequest request : requests) {
                  appended.add(appendInTransaction(request, false));
                }
                return List.copyOf(appended);
              });
      if (result == null) throw new IllegalStateException("Ledger 事务未返回批次追加结果");
      return result;
    }
  }

  public List<AgentLedgerRecord> read(String runId, String nodeRunId) {
    requireId(runId, "runId", 80);
    requireId(nodeRunId, "nodeRunId", 80);
    return List.copyOf(repository.findByRunIdAndNodeRunIdOrderBySequenceAsc(runId, nodeRunId));
  }

  public StateSnapshot state(Long projectId, String runId, String nodeRunId) {
    requirePositiveId(projectId, "projectId");
    requireId(runId, "runId", 80);
    requireId(nodeRunId, "nodeRunId", 80);
    List<AgentLedgerRecord> entries =
        List.copyOf(
            repository.findByProjectIdAndRunIdAndNodeRunIdOrderBySequenceAsc(
                projectId, runId, nodeRunId));
    if (entries.isEmpty()) return StateSnapshot.notFound(runId, nodeRunId);
    VerificationResult verification = verifyEntries(entries);
    if (!verification.valid()) {
      return StateSnapshot.invalid(runId, nodeRunId, verification.reason());
    }
    AgentLedgerRecord last = lastEffectiveEntry(entries);
    return new StateSnapshot(
        true,
        true,
        verification.terminal(),
        verification.reason(),
        runId,
        nodeRunId,
        last.getOuterNodeId(),
        last.getStatus(),
        last.getInnerStep(),
        last.getSequence(),
        verification.entryCount(),
        verification.headDigest(),
        last.getWorkflowId(),
        last.getWorkflowRevision(),
        last.getWorkflowDigest(),
        last.getPolicyRevision(),
        entries.get(0).getCreatedAt(),
        entries.get(entries.size() - 1).getCreatedAt());
  }

  public VerificationResult verify(String runId, String nodeRunId) {
    return verifyEntries(read(runId, nodeRunId));
  }

  private VerificationResult verifyEntries(List<AgentLedgerRecord> entries) {
    String previous = null;
    boolean terminal = false;
    long expectedSequence = 1;
    AgentLedgerRecord chainStart = entries.isEmpty() ? null : entries.get(0);
    for (AgentLedgerRecord entry : entries) {
      if (entry.getSequence() != expectedSequence) {
        return VerificationResult.invalid(expectedSequence, "SEQUENCE_GAP");
      }
      if (!Objects.equals(previous, entry.getPreviousEntryDigest())) {
        return VerificationResult.invalid(expectedSequence, "PREVIOUS_DIGEST_MISMATCH");
      }
      if (terminal && !isCorrection(entry)) {
        return VerificationResult.invalid(expectedSequence, "ENTRY_AFTER_TERMINAL");
      }
      if (!sameChainContext(chainStart, entry)) {
        return VerificationResult.invalid(expectedSequence, "CHAIN_CONTEXT_MISMATCH");
      }
      String expectedDigest = digest(canonicalPayload(entry));
      if (!MessageDigest.isEqual(
          expectedDigest.getBytes(StandardCharsets.US_ASCII),
          entry.getEntryDigest().getBytes(StandardCharsets.US_ASCII))) {
        return VerificationResult.invalid(expectedSequence, "ENTRY_DIGEST_MISMATCH");
      }
      terminal = terminal || TERMINAL_STATUSES.contains(entry.getStatus());
      previous = entry.getEntryDigest();
      expectedSequence++;
    }
    return new VerificationResult(true, entries.size(), previous, terminal, "OK");
  }

  /**
   * Computes a recovery eligibility decision from persisted public facts only. This method never
   * invokes Python, resumes an in-memory state, creates tasks, or reuses an approval decision.
   */
  public RecoveryDecision evaluateRecovery(RecoveryRequest rawRequest) {
    RecoveryRequest request = normalizeRecovery(rawRequest);
    List<AgentLedgerRecord> entries =
        repository.findByProjectIdAndRunIdAndNodeRunIdOrderBySequenceAsc(
            request.projectId(), request.runId(), request.nodeRunId());
    if (entries.isEmpty()) return RecoveryDecision.denied("NOT_FOUND", null, 0, null, false);

    VerificationResult verification = verifyEntries(entries);
    if (!verification.valid()) {
      return RecoveryDecision.denied(
          "CORRUPT_LEDGER", null, verification.entryCount(), null, false);
    }
    AgentLedgerRecord last = lastEffectiveEntry(entries);
    if (!Objects.equals(last.getProjectId(), request.projectId())
        || !Objects.equals(last.getTargetId(), request.targetId())) {
      return RecoveryDecision.denied(
          "SCOPE_MISMATCH", null, verification.entryCount(), verification.headDigest(), false);
    }
    if (!Objects.equals(last.getWorkflowId(), request.workflowId())
        || !Objects.equals(last.getWorkflowDigest(), request.workflowDigest())) {
      return RecoveryDecision.denied(
          "STALE_WORKFLOW",
          "STALE_WORKFLOW",
          verification.entryCount(),
          verification.headDigest(),
          false);
    }
    if (!Objects.equals(last.getPolicyRevision(), request.policyRevision())) {
      return RecoveryDecision.denied(
          "STALE_POLICY", null, verification.entryCount(), verification.headDigest(), false);
    }
    Instant latestCreatedAt = entries.get(entries.size() - 1).getCreatedAt();
    if (latestCreatedAt.isBefore(request.resumeNotBefore())) {
      return RecoveryDecision.denied(
          "RECOVERY_WINDOW_EXPIRED",
          null,
          verification.entryCount(),
          verification.headDigest(),
          false);
    }

    if (verification.terminal()) {
      if ("APPROVAL_REQUIRED".equals(last.getStatus())) {
        return RecoveryDecision.denied(
            "FRESH_APPROVAL_REQUIRED",
            last.getStatus(),
            verification.entryCount(),
            verification.headDigest(),
            true);
      }
      if ("FAILED".equals(last.getStatus())) {
        return RecoveryDecision.denied(
            "FAILED_RETRY_POLICY_REQUIRED",
            last.getStatus(),
            verification.entryCount(),
            verification.headDigest(),
            false);
      }
      return RecoveryDecision.denied(
          "ALREADY_TERMINAL",
          last.getStatus(),
          verification.entryCount(),
          verification.headDigest(),
          false);
    }

    if (!isLatestUnterminatedNode(request, entries)) {
      return RecoveryDecision.denied(
          "NOT_LATEST_UNTERMINATED_NODE",
          last.getStatus(),
          verification.entryCount(),
          verification.headDigest(),
          false);
    }
    return new RecoveryDecision(
        true,
        "RESUMABLE_FROM_LEDGER",
        last.getStatus(),
        last.getSequence(),
        verification.entryCount(),
        verification.headDigest(),
        last.getInnerStep(),
        false);
  }

  private AgentLedgerRecord append(AppendRequest rawRequest, boolean correction) {
    AppendRequest request = normalize(rawRequest);
    if (correction) requireCorrection(request);
    if (!correction
        && (CORRECTION_EVENT_TYPE.equals(request.eventType())
            || CORRECTION_STATUS.equals(request.status()))) {
      throw new ApiException("审计修正必须使用独立追加入口");
    }
    Object lock = appendLocks[Math.floorMod(chainKey(request).hashCode(), appendLocks.length)];
    synchronized (lock) {
      AgentLedgerRecord result =
          transaction.execute(ignored -> appendInTransaction(request, correction));
      if (result == null) throw new IllegalStateException("Ledger 事务未返回追加结果");
      return result;
    }
  }

  private AgentLedgerRecord appendInTransaction(AppendRequest request, boolean correction) {
    AgentLedgerRecord duplicate =
        repository
            .findByRunIdAndNodeRunIdAndSequence(
                request.runId(), request.nodeRunId(), request.sequence())
            .orElse(null);
    if (duplicate != null) {
      if (sameLogicalEntry(duplicate, request)) return duplicate;
      throw new ApiException("Ledger 序列已被不同事件占用");
    }

    AgentLedgerRecord previous =
        repository
            .findFirstByRunIdAndNodeRunIdOrderBySequenceDesc(
                request.runId(), request.nodeRunId())
            .orElse(null);
    if (previous != null && !sameChainContext(previous, request)) {
      throw new ApiException("Ledger 链上下文不一致");
    }
    long expectedSequence = previous == null ? 1 : previous.getSequence() + 1;
    if (request.sequence() != expectedSequence) {
      throw new ApiException("Ledger sequence 必须严格连续");
    }
    boolean terminal =
        repository.existsByRunIdAndNodeRunIdAndStatusIn(
            request.runId(), request.nodeRunId(), TERMINAL_STATUSES);
    if (correction && !terminal) throw new ApiException("只有终态 Ledger 可以追加审计修正");
    if (!correction && terminal) throw new ApiException("Ledger 已进入终态，不能继续追加普通事件");

    String evidenceJson = writeCanonical(request.evidenceIds());
    String actionJson = writeCanonical(request.actionIds());
    String previousDigest = previous == null ? null : previous.getEntryDigest();
    Instant createdAt = Instant.now();
    String entryDigest =
        digest(
            canonicalPayload(
                request, evidenceJson, actionJson, previousDigest, createdAt, LEDGER_REVISION));
    AgentLedgerRecord record =
        new AgentLedgerRecord(
            request,
            evidenceJson,
            actionJson,
            LEDGER_REVISION,
            previousDigest,
            entryDigest,
            createdAt);
    return repository.saveAndFlush(record);
  }

  private AppendRequest normalize(AppendRequest request) {
    if (request == null) throw new ApiException("Ledger 事件不能为空");
    requireId(request.runId(), "runId", 80);
    requirePositiveId(request.projectId(), "projectId");
    requirePositiveId(request.targetId(), "targetId");
    requireId(request.workflowId(), "workflowId", 80);
    if (request.workflowRevision() <= 0) throw new ApiException("workflowRevision 无效");
    requireDigest(request.workflowDigest(), "workflowDigest");
    requireId(request.outerNodeId(), "outerNodeId", 64);
    requireId(request.nodeRunId(), "nodeRunId", 80);
    if (request.sequence() <= 0) throw new ApiException("Ledger sequence 无效");
    requireId(request.innerStep(), "innerStep", 64);
    requireId(request.eventType(), "eventType", 64);
    requireId(request.status(), "status", 32);
    requireDigest(request.inputDigest(), "inputDigest");
    requireDigest(request.outputDigest(), "outputDigest");
    requireId(request.policyRevision(), "policyRevision", 80);
    requireId(request.indexRevision(), "indexRevision", 100);
    return new AppendRequest(
        request.runId(),
        request.workflowId(),
        request.workflowRevision(),
        request.workflowDigest(),
        request.outerNodeId(),
        request.nodeRunId(),
        request.sequence(),
        request.innerStep(),
        request.eventType(),
        request.status(),
        request.inputDigest(),
        request.outputDigest(),
        normalizeReferences(request.evidenceIds(), "evidenceIds"),
        normalizeReferences(request.actionIds(), "actionIds"),
        request.policyRevision(),
        request.indexRevision(),
        request.projectId(),
        request.targetId());
  }

  private RecoveryRequest normalizeRecovery(RecoveryRequest request) {
    if (request == null) throw new ApiException("Ledger 恢复请求不能为空");
    requirePositiveId(request.projectId(), "projectId");
    requirePositiveId(request.targetId(), "targetId");
    requireId(request.runId(), "runId", 80);
    requireId(request.nodeRunId(), "nodeRunId", 80);
    requireId(request.workflowId(), "workflowId", 80);
    if (request.workflowRevision() <= 0) throw new ApiException("workflowRevision 无效");
    requireDigest(request.workflowDigest(), "workflowDigest");
    requireId(request.policyRevision(), "policyRevision", 80);
    if (request.resumeNotBefore() == null) throw new ApiException("Ledger 恢复时间窗不能为空");
    return request;
  }

  private void requireCorrection(AppendRequest request) {
    if (!CORRECTION_EVENT_TYPE.equals(request.eventType())
        || !CORRECTION_STATUS.equals(request.status())
        || !"audit".equals(request.innerStep())
        || !request.evidenceIds().isEmpty()
        || !request.actionIds().isEmpty()) {
      throw new ApiException("审计修正事件格式无效");
    }
  }

  private List<String> normalizeReferences(List<String> values, String field) {
    if (values == null || values.isEmpty()) return List.of();
    if (values.size() > MAX_REFERENCES) throw new ApiException(field + " 数量超过限制");
    List<String> normalized = new ArrayList<>();
    for (String value : values) {
      requireId(value, field, 128);
      if (!normalized.contains(value)) normalized.add(value);
    }
    Collections.sort(normalized);
    return List.copyOf(normalized);
  }

  private void requireId(String value, String field, int maxLength) {
    if (value == null
        || value.isBlank()
        || value.length() > maxLength
        || !SAFE_ID.matcher(value).matches()) {
      throw new ApiException("Ledger " + field + " 格式无效");
    }
  }

  private void requireDigest(String value, String field) {
    if (value == null || !SHA256.matcher(value).matches()) {
      throw new ApiException("Ledger " + field + " 必须是 SHA-256 摘要");
    }
  }

  private void requirePositiveId(Long value, String field) {
    if (value == null || value <= 0) throw new ApiException("Ledger " + field + " 无效");
  }

  private boolean sameLogicalEntry(AgentLedgerRecord record, AppendRequest request) {
    return record.getWorkflowRevision() == request.workflowRevision()
        && record.getSequence() == request.sequence()
        && Objects.equals(record.getRunId(), request.runId())
        && Objects.equals(record.getProjectId(), request.projectId())
        && Objects.equals(record.getTargetId(), request.targetId())
        && Objects.equals(record.getWorkflowId(), request.workflowId())
        && Objects.equals(record.getWorkflowDigest(), request.workflowDigest())
        && Objects.equals(record.getOuterNodeId(), request.outerNodeId())
        && Objects.equals(record.getNodeRunId(), request.nodeRunId())
        && Objects.equals(record.getInnerStep(), request.innerStep())
        && Objects.equals(record.getEventType(), request.eventType())
        && Objects.equals(record.getStatus(), request.status())
        && Objects.equals(record.getInputDigest(), request.inputDigest())
        && Objects.equals(record.getOutputDigest(), request.outputDigest())
        && Objects.equals(record.getEvidenceIdsJson(), writeCanonical(request.evidenceIds()))
        && Objects.equals(record.getActionIdsJson(), writeCanonical(request.actionIds()))
        && Objects.equals(record.getPolicyRevision(), request.policyRevision())
        && Objects.equals(record.getIndexRevision(), request.indexRevision());
  }

  private boolean sameChainContext(AgentLedgerRecord left, AgentLedgerRecord right) {
    if (left == null || right == null) return true;
    return left.getWorkflowRevision() == right.getWorkflowRevision()
        && Objects.equals(left.getRunId(), right.getRunId())
        && Objects.equals(left.getProjectId(), right.getProjectId())
        && Objects.equals(left.getTargetId(), right.getTargetId())
        && Objects.equals(left.getWorkflowId(), right.getWorkflowId())
        && Objects.equals(left.getWorkflowDigest(), right.getWorkflowDigest())
        && Objects.equals(left.getOuterNodeId(), right.getOuterNodeId())
        && Objects.equals(left.getNodeRunId(), right.getNodeRunId())
        && Objects.equals(left.getPolicyRevision(), right.getPolicyRevision());
  }

  private boolean sameChainContext(AgentLedgerRecord record, AppendRequest request) {
    return record.getWorkflowRevision() == request.workflowRevision()
        && Objects.equals(record.getRunId(), request.runId())
        && Objects.equals(record.getProjectId(), request.projectId())
        && Objects.equals(record.getTargetId(), request.targetId())
        && Objects.equals(record.getWorkflowId(), request.workflowId())
        && Objects.equals(record.getWorkflowDigest(), request.workflowDigest())
        && Objects.equals(record.getOuterNodeId(), request.outerNodeId())
        && Objects.equals(record.getNodeRunId(), request.nodeRunId())
        && Objects.equals(record.getPolicyRevision(), request.policyRevision());
  }

  private AgentLedgerRecord lastEffectiveEntry(List<AgentLedgerRecord> entries) {
    for (int index = entries.size() - 1; index >= 0; index--) {
      AgentLedgerRecord entry = entries.get(index);
      if (!isCorrection(entry)) return entry;
    }
    throw new IllegalStateException("Ledger 链缺少普通事件");
  }

  private boolean isLatestUnterminatedNode(
      RecoveryRequest request, List<AgentLedgerRecord> requestedEntries) {
    List<AgentLedgerRecord> runEntries =
        repository.findByProjectIdAndRunIdOrderByCreatedAtAscLedgerIdAsc(
            request.projectId(), request.runId());
    Map<String, List<AgentLedgerRecord>> chains = new LinkedHashMap<>();
    for (AgentLedgerRecord entry : runEntries) {
      chains.computeIfAbsent(entry.getNodeRunId(), ignored -> new ArrayList<>()).add(entry);
    }
    String latestNodeRunId = null;
    Instant latestActivity = null;
    long latestLedgerId = Long.MIN_VALUE;
    for (Map.Entry<String, List<AgentLedgerRecord>> chain : chains.entrySet()) {
      VerificationResult verification = verifyEntries(chain.getValue());
      if (!verification.valid()) return false;
      if (verification.terminal()) continue;
      AgentLedgerRecord latest = chain.getValue().get(chain.getValue().size() - 1);
      if (latestActivity == null
          || latest.getCreatedAt().isAfter(latestActivity)
          || (latest.getCreatedAt().equals(latestActivity)
              && latest.getLedgerId() > latestLedgerId)) {
        latestNodeRunId = chain.getKey();
        latestActivity = latest.getCreatedAt();
        latestLedgerId = latest.getLedgerId();
      }
    }
    return !requestedEntries.isEmpty() && Objects.equals(request.nodeRunId(), latestNodeRunId);
  }

  private boolean isCorrection(AgentLedgerRecord entry) {
    return CORRECTION_EVENT_TYPE.equals(entry.getEventType())
        && CORRECTION_STATUS.equals(entry.getStatus())
        && "audit".equals(entry.getInnerStep())
        && "[]".equals(entry.getEvidenceIdsJson())
        && "[]".equals(entry.getActionIdsJson());
  }

  private Map<String, Object> canonicalPayload(AgentLedgerRecord entry) {
    Map<String, Object> values = new LinkedHashMap<>();
    values.put("runId", entry.getRunId());
    values.put("projectId", entry.getProjectId());
    values.put("targetId", entry.getTargetId());
    values.put("workflowId", entry.getWorkflowId());
    values.put("workflowRevision", entry.getWorkflowRevision());
    values.put("workflowDigest", entry.getWorkflowDigest());
    values.put("outerNodeId", entry.getOuterNodeId());
    values.put("nodeRunId", entry.getNodeRunId());
    values.put("sequence", entry.getSequence());
    values.put("innerStep", entry.getInnerStep());
    values.put("eventType", entry.getEventType());
    values.put("status", entry.getStatus());
    values.put("inputDigest", entry.getInputDigest());
    values.put("outputDigest", entry.getOutputDigest());
    values.put("evidenceIdsJson", entry.getEvidenceIdsJson());
    values.put("actionIdsJson", entry.getActionIdsJson());
    values.put("policyRevision", entry.getPolicyRevision());
    values.put("indexRevision", entry.getIndexRevision());
    values.put("ledgerRevision", entry.getLedgerRevision());
    values.put("previousEntryDigest", Objects.toString(entry.getPreviousEntryDigest(), ""));
    values.put("createdAt", entry.getCreatedAt().toString());
    return new TreeMap<>(values);
  }

  private Map<String, Object> canonicalPayload(
      AppendRequest request,
      String evidenceJson,
      String actionJson,
      String previousDigest,
      Instant createdAt,
      String ledgerRevision) {
    Map<String, Object> values = new LinkedHashMap<>();
    values.put("runId", request.runId());
    values.put("projectId", request.projectId());
    values.put("targetId", request.targetId());
    values.put("workflowId", request.workflowId());
    values.put("workflowRevision", request.workflowRevision());
    values.put("workflowDigest", request.workflowDigest());
    values.put("outerNodeId", request.outerNodeId());
    values.put("nodeRunId", request.nodeRunId());
    values.put("sequence", request.sequence());
    values.put("innerStep", request.innerStep());
    values.put("eventType", request.eventType());
    values.put("status", request.status());
    values.put("inputDigest", request.inputDigest());
    values.put("outputDigest", request.outputDigest());
    values.put("evidenceIdsJson", evidenceJson);
    values.put("actionIdsJson", actionJson);
    values.put("policyRevision", request.policyRevision());
    values.put("indexRevision", request.indexRevision());
    values.put("ledgerRevision", ledgerRevision);
    values.put("previousEntryDigest", Objects.toString(previousDigest, ""));
    values.put("createdAt", createdAt.toString());
    return new TreeMap<>(values);
  }

  private String digest(Map<String, Object> canonicalPayload) {
    try {
      byte[] canonical = canonicalMapper.writeValueAsBytes(canonicalPayload);
      byte[] hashed = MessageDigest.getInstance("SHA-256").digest(canonical);
      return "sha256:" + java.util.HexFormat.of().formatHex(hashed);
    } catch (Exception ex) {
      throw new IllegalStateException("Ledger 摘要计算失败", ex);
    }
  }

  private String writeCanonical(Object value) {
    try {
      return canonicalMapper.writeValueAsString(value);
    } catch (JsonProcessingException ex) {
      throw new IllegalStateException("Ledger 引用序列化失败", ex);
    }
  }

  private String chainKey(AppendRequest request) {
    return request.runId() + '\u0000' + request.nodeRunId();
  }

  public record AppendRequest(
      String runId,
      String workflowId,
      long workflowRevision,
      String workflowDigest,
      String outerNodeId,
      String nodeRunId,
      long sequence,
      String innerStep,
      String eventType,
      String status,
      String inputDigest,
      String outputDigest,
      List<String> evidenceIds,
      List<String> actionIds,
      String policyRevision,
      String indexRevision,
      Long projectId,
      Long targetId) {
    /** Compile compatibility only; append rejects missing scope identifiers. */
    public AppendRequest(
        String runId,
        String workflowId,
        long workflowRevision,
        String workflowDigest,
        String outerNodeId,
        String nodeRunId,
        long sequence,
        String innerStep,
        String eventType,
        String status,
        String inputDigest,
        String outputDigest,
        List<String> evidenceIds,
        List<String> actionIds,
        String policyRevision,
        String indexRevision) {
      this(
          runId,
          workflowId,
          workflowRevision,
          workflowDigest,
          outerNodeId,
          nodeRunId,
          sequence,
          innerStep,
          eventType,
          status,
          inputDigest,
          outputDigest,
          evidenceIds,
          actionIds,
          policyRevision,
          indexRevision,
          null,
          null);
    }
  }

  public record RecoveryRequest(
      Long projectId,
      Long targetId,
      String runId,
      String nodeRunId,
      String workflowId,
      long workflowRevision,
      String workflowDigest,
      String policyRevision,
      Instant resumeNotBefore) {}

  public record RecoveryDecision(
      boolean resumable,
      String reason,
      String status,
      long lastSequence,
      long entryCount,
      String headDigest,
      String resumeFromInnerStep,
      boolean freshApprovalRequired) {
    private static RecoveryDecision denied(
        String reason,
        String status,
        long entryCount,
        String headDigest,
        boolean freshApprovalRequired) {
      return new RecoveryDecision(
          false, reason, status, 0, entryCount, headDigest, null, freshApprovalRequired);
    }
  }

  public record StateSnapshot(
      boolean found,
      boolean valid,
      boolean terminal,
      String reason,
      String runId,
      String nodeRunId,
      String outerNodeId,
      String status,
      String innerStep,
      long lastSequence,
      long entryCount,
      String headDigest,
      String workflowId,
      long workflowRevision,
      String workflowDigest,
      String policyRevision,
      Instant startedAt,
      Instant updatedAt) {
    private static StateSnapshot notFound(String runId, String nodeRunId) {
      return new StateSnapshot(
          false,
          true,
          false,
          "NOT_FOUND",
          runId,
          nodeRunId,
          null,
          null,
          null,
          0,
          0,
          null,
          null,
          0,
          null,
          null,
          null,
          null);
    }

    private static StateSnapshot invalid(String runId, String nodeRunId, String reason) {
      return new StateSnapshot(
          true,
          false,
          false,
          reason,
          runId,
          nodeRunId,
          null,
          null,
          null,
          0,
          0,
          null,
          null,
          0,
          null,
          null,
          null,
          null);
    }
  }

  public record VerificationResult(
      boolean valid,
      long entryCount,
      String headDigest,
      boolean terminal,
      String reason) {
    private static VerificationResult invalid(long entriesChecked, String reason) {
      return new VerificationResult(false, entriesChecked - 1, null, false, reason);
    }
  }
}
