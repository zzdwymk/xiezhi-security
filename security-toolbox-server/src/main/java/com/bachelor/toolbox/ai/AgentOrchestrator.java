package com.bachelor.toolbox.ai;

import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.settings.BusinessDataOperationGate;
import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/**
 * Project-scoped red-team assessment orchestration.
 *
 * <p>The public lifecycle follows engagement, reconnaissance, mapping, discovery, validation,
 * impact assessment, retest and reporting. Authorization and review remain mandatory internal
 * controls at every execution boundary, but they are not exposed as a separate user workflow.
 */
@Service
public class AgentOrchestrator {
  private static final Set<String> SENSITIVE_PUBLIC_DATA_KEYS =
      Set.of(
          "apikey",
          "authorization",
          "chainofthought",
          "content",
          "cot",
          "credential",
          "credentials",
          "evidencetext",
          "evidencebody",
          "evidencecontent",
          "fullevidence",
          "prompt",
          "originalprompt",
          "userprompt",
          "rawprompt",
          "rawevidence",
          "reasoning",
          "secret",
          "snippet",
          "systemprompt",
          "text",
          "token",
          "accesstoken",
          "refreshtoken",
          "password");
  private final AiConversationMemoryService memory;
  private final SecurityAgentTools tools;
  private final AiAgentRuntimeClient runtimeClient;
  private final AiProjectIndexService projectIndex;
  private final AiPlanningService planner;
  private final AiAuthorizationGuard guard;
  private final AiExecutionReviewer reviewer;
  private final AiContextService contextService;
  private final AuditService audit;
  private final BusinessDataOperationGate operationGate;

  @Autowired
  public AgentOrchestrator(
      AiConversationMemoryService memory,
      SecurityAgentTools tools,
      AiAgentRuntimeClient runtimeClient,
      AiProjectIndexService projectIndex,
      AiPlanningService planner,
      AiAuthorizationGuard guard,
      AiExecutionReviewer reviewer,
      AiContextService contextService,
      AuditService audit,
      BusinessDataOperationGate operationGate) {
    this.memory = memory;
    this.tools = tools;
    this.runtimeClient = runtimeClient;
    this.projectIndex = projectIndex;
    this.planner = planner;
    this.guard = guard;
    this.reviewer = reviewer;
    this.contextService = contextService;
    this.audit = audit;
    this.operationGate = operationGate;
  }

  AgentOrchestrator(
      AiConversationMemoryService memory,
      SecurityAgentTools tools,
      AiAgentRuntimeClient runtimeClient,
      AiProjectIndexService projectIndex,
      AiPlanningService planner,
      AiAuthorizationGuard guard,
      AiExecutionReviewer reviewer,
      AuditService audit) {
    this(
        memory,
        tools,
        runtimeClient,
        projectIndex,
        planner,
        guard,
        reviewer,
        null,
        audit,
        new BusinessDataOperationGate());
  }

  AgentOrchestrator(
      AiConversationMemoryService memory,
      SecurityAgentTools tools,
      AiAgentRuntimeClient runtimeClient,
      AiProjectIndexService projectIndex,
      AiPlanningService planner,
      AiAuthorizationGuard guard,
      AiExecutionReviewer reviewer,
      AiContextService contextService,
      AuditService audit) {
    this(
        memory,
        tools,
        runtimeClient,
        projectIndex,
        planner,
        guard,
        reviewer,
        contextService,
        audit,
        new BusinessDataOperationGate());
  }

  public AiAgentResponse run(AiAgentRequest request) {
    return run(request, ignored -> {});
  }

  public AiAgentResponse run(AiAgentRequest request, Consumer<AiAgentEvent> eventSink) {
    return operationGate.withMutation(() -> runUnderGate(request, eventSink));
  }

  private AiAgentResponse runUnderGate(
      AiAgentRequest request, Consumer<AiAgentEvent> eventSink) {
    Consumer<AiAgentEvent> sink = eventSink == null ? ignored -> {} : eventSink;
    EventSequence sequence = new EventSequence(request);
    TurnProvenance provenance = new TurnProvenance();
    TurnExecutionState executionState = new TurnExecutionState();
    AiConversationMemoryService.SessionHandle session =
        memory.open(request.sessionId(), request.projectId(), request.targetId());

    synchronized (session.monitor()) {
      try {
        emit(
            sink,
            sequence,
            "state",
            AgentPhase.SESSION,
            "READY",
            "AI 会话已绑定当前评估项目和授权目标",
            Map.of(
                "sessionId",
                session.id(),
                "projectId",
                request.projectId(),
                "targetId",
                request.targetId()));

        String history = memory.transcript(session.id());
        memory.addUser(session.id(), request.prompt());
        Optional<String> directAuditAnswer =
            contextService == null
                ? Optional.empty()
                : contextService.answerAuditQuestion(
                    request.projectId(),
                    request.targetId(),
                    request.contextRefs(),
                    request.refs(),
                    request.prompt(),
                    request.mode());
        if (directAuditAnswer.isPresent()) {
          String answer = directAuditAnswer.get();
          return completeInformationalTurn(
              request,
              session,
              sink,
              sequence,
              new AiPlanResponse("audit-analysis", "", answer, false, List.of()),
              answer,
              provenance);
        }

        if (isSimpleGreeting(request.prompt())) {
          String answer = "你好，我可以帮你分析授权目标、流量、检测任务和安全结果。";
          return completeInformationalTurn(
              request,
              session,
              sink,
              sequence,
              new AiPlanResponse("local-greeting", "", answer, false, List.of()),
              answer,
              provenance);
        }

        emit(
            sink,
            sequence,
            "state",
            AgentPhase.ENGAGEMENT,
            "LOADING_CONTEXT",
            "正在读取项目、目标、授权记录和历史证据",
            Map.of());
        // This is deliberately a non-execution context read.  It must remain available
        // for project introductions and historical-result questions after an engagement
        // expires; the strict authorization guard runs only if a plan is actually
        // confirmed for execution.
        String scope = tools.inspectProjectContext(request.projectId(), request.targetId());
        emit(
            sink,
            sequence,
            "state",
            AgentPhase.ENGAGEMENT,
            "CONTEXT_READY",
            "项目与目标上下文已载入；执行授权将在工具计划确认后重新校验",
            Map.of("scope", scope));

        boolean indexReady = projectIndex.refreshBestEffort(request.projectId());
        emit(
            sink,
            sequence,
            "state",
            AgentPhase.RECONNAISSANCE,
            indexReady ? "INDEX_READY" : "INDEX_DEGRADED",
            indexReady ? "项目授权、目标、任务、漏洞和信息收集摘要已同步到本地知识索引" : "本地知识索引暂不可用，将继续使用数据库实时上下文",
            Map.of(
                "projectId",
                request.projectId(),
                "indexEngine",
                "llama-index",
                "available",
                indexReady));

        String planningPrompt =
            history.isBlank()
                ? request.prompt()
                : "以下是同一项目和目标内最近的对话记忆：\n" + history + "\n\n当前请求：" + request.prompt();
        planningPrompt += "\n\n服务端授权上下文：" + scope;

        emit(
            sink,
            sequence,
            "state",
            AgentPhase.ENGAGEMENT,
            "RUNNING",
            "正在根据当前目标生成红队评估行动方案",
            Map.of());
        AiPlanRequest planRequest =
            new AiPlanRequest(
                request.projectId(),
                request.targetId(),
                planningPrompt,
                request.contextRefs(),
                request.refs(),
                request.mode());
        // Prefer the local AI Runtime for natural-language intent understanding.
        // Java planner is a progressive hint / offline fallback only — keyword rules
        // must not block the model from seeing the user turn.
        AiPlanResponse proposed = null;
        if (!runtimeClient.enabled()) {
          provenance.markFallback("RUNTIME_DISABLED");
          if (request.executionRequested()) {
            throw new ApiException(
                "AI Runtime 未启用，无法建立受信任的 v3 Ledger 证据链，本轮执行已安全停止");
          }
          proposed =
              planner.planStreaming(
                  planRequest,
                  modelEvent -> {
                    String text = safe(modelEvent.text(), 1000);
                    Map<String, Object> data = new LinkedHashMap<>();
                    data.put("modelEvent", modelEvent.type());
                    if (!text.isBlank()) data.put("detail", text);
                    emit(
                        sink,
                        sequence,
                        "planner_progress",
                        AgentPhase.ENGAGEMENT,
                        "RUNNING",
                        text.isBlank() ? "正在理解当前请求" : text,
                        data);
                   });
          provenance.setJavaPlannerSource(proposed);
        } else {
          emit(
              sink,
              sequence,
              "planner_progress",
              AgentPhase.ENGAGEMENT,
              "RUNNING",
              "正在由 AI 理解你的意图并规划下一步",
              Map.of("runtimeFirst", true));
        }
        String runtimeAnswer = "";
        if (runtimeClient.enabled()) {
          AiAgentRequest runtimeRequest =
              new AiAgentRequest(
                  request.projectId(),
                  request.targetId(),
                  session.id(),
                  request.prompt(),
                  request.execute(),
                  request.contextRefs(),
                  request.refs(),
                  request.mode(),
                  request.turnId(),
                  request.workflowId(),
                  request.workflowRevision(),
                  request.workflowDigest(),
                  request.outerNodeId(),
                  request.nodeRunId());
          try {
            AiAgentRuntimeClient.RuntimePlanResult runtimeResult =
                runtimeClient.plan(
                    runtimeRequest,
                    planningPrompt,
                    runtimeEvent -> {
                      provenance.accept(runtimeEvent);
                      emitRuntimeEvent(sink, sequence, runtimeEvent);
                    });
            proposed = runtimeResult.plan();
            runtimeAnswer = runtimeResult.answer();
            provenance.apply(runtimeResult.provenance());
            provenance.setRuntimeRunId(runtimeResult.runId());
            // The runtime is allowed to downgrade an ambiguous request to an
            // answer/clarification.  Never keep the preliminary Java steps in that
            // case; an empty runtime plan is an explicit no-execution decision.
            if (runtimeResult.plan() != null) proposed = runtimeResult.plan();
            emit(
                sink,
                sequence,
                "planner_progress",
                AgentPhase.ENGAGEMENT,
                "RUNTIME_COMPLETED",
                !hasSteps(proposed) ? "本地智能体判断当前请求无需执行工具" : "本地智能体运行时已生成行动方案；具体任务仍由受控执行边界派发",
                provenance.eventData(Map.of("runtimeStatus", runtimeResult.status())));
          } catch (AiAgentRuntimeClient.RuntimeProtocolException ex) {
            provenance.markProtocolRejected();
            String runtimeMessage = ex.getMessage();
            if (runtimeMessage != null && runtimeMessage.contains("TURN_TIMEOUT")) {
              throw new ApiException(
                  "模型在规定时间内没有完成回答，本轮已停止，未执行任何检测，请检查模型连接后重试");
            }
            if (runtimeMessage != null && runtimeMessage.contains("MODEL_ACCESS_DENIED")) {
              throw new ApiException(
                  "模型服务拒绝了这次请求，本轮已停止，未执行任何检测。请检查代理权限、模型权限，或改用兼容的模型服务后重试");
            }
            if (runtimeMessage != null && runtimeMessage.contains("MODEL_RATE_LIMITED")) {
              throw new ApiException(
                  "模型服务当前请求过多，本轮已停止，未执行任何检测。请稍后重试");
            }
            if (runtimeMessage != null && runtimeMessage.contains("MODEL_TIMEOUT")) {
              throw new ApiException(
                  "模型服务连接超时，本轮已停止，未执行任何检测。请检查服务状态后重试");
            }
            if (runtimeMessage != null && runtimeMessage.contains("MODEL_SERVICE_UNAVAILABLE")) {
              throw new ApiException(
                  "模型服务暂时不可用，本轮已停止，未执行任何检测。请检查服务状态后重试");
            }
            if (runtimeMessage != null && runtimeMessage.contains("MODEL_REQUEST_FAILED")) {
              throw new ApiException(
                  "模型服务请求失败，本轮已停止，未执行任何检测。请检查模型地址和连接后重试");
            }
            throw new ApiException(
                "AI Runtime 返回内容未通过 Harness 协议校验：智能服务返回内容格式不完整，本轮已安全停止，请检查模型连接后重试");
          } catch (AiAgentRuntimeClient.RuntimeUnavailableException ex) {
            provenance.markFallback("RUNTIME_UNAVAILABLE");
            if (request.executionRequested()) {
              throw new ApiException(
                  "AI Runtime 当前不可用，无法建立受信任的 v3 Ledger 证据链，本轮执行已安全停止");
            }
            emit(
                sink,
                sequence,
                "planner_progress",
                AgentPhase.ENGAGEMENT,
                "LOCAL_FALLBACK",
                "本地 AI Runtime 不可用，改由 Java 规划器理解意图",
                provenance.eventData(Map.of()));
            proposed =
                planner.planStreaming(
                    planRequest,
                    modelEvent -> {
                      String text = safe(modelEvent.text(), 1000);
                      Map<String, Object> data = new LinkedHashMap<>();
                      data.put("modelEvent", modelEvent.type());
                      if (!text.isBlank()) data.put("detail", text);
                      emit(
                          sink,
                          sequence,
                          "planner_progress",
                          AgentPhase.ENGAGEMENT,
                          "RUNNING",
                          text.isBlank() ? "正在理解当前请求" : text,
                          data);
                    });
            provenance.setJavaPlannerSource(proposed);
          }
        }
        if (proposed == null) {
          proposed =
              planner.planStreaming(
                  planRequest,
                  modelEvent -> {
                    String text = safe(modelEvent.text(), 1000);
                    Map<String, Object> data = new LinkedHashMap<>();
                    data.put("modelEvent", modelEvent.type());
                    if (!text.isBlank()) data.put("detail", text);
                    emit(
                        sink,
                        sequence,
                        "planner_progress",
                        AgentPhase.ENGAGEMENT,
                        "RUNNING",
                        text.isBlank() ? "正在理解当前请求" : text,
                        data);
                  });
          if (provenance.fallback) provenance.setJavaPlannerSource(proposed);
        }
        if (request.executionRequested()
            && hasSteps(proposed)
            && provenance.fallback
            && !"PYTHON_MODEL_FALLBACK".equals(provenance.fallbackReason)) {
          throw new ApiException(
              "AI Runtime 未完成受信任的 v3 Ledger 证据链，本轮执行已安全停止；恢复 Runtime 后请使用同一 Turn 重试");
        }
        if (!hasSteps(proposed)) {
          String answer =
              runtimeAnswer == null || runtimeAnswer.isBlank()
                  ? safe(proposed == null ? "我已理解你的问题，但本轮不需要执行检测工具。" : proposed.summary(), 4000)
                  : safe(runtimeAnswer, 4000);
          return completeInformationalTurn(
              request,
              session,
              sink,
              sequence,
              proposed == null
                  ? new AiPlanResponse("local-rule", "", answer, false, List.of())
                  : proposed,
              answer,
              provenance);
        }
        {
          Map<String, Object> planData = new LinkedHashMap<>();
          planData.put("plan", proposed);
          planData.put("steps", proposed.steps() == null ? List.of() : proposed.steps());
          planData.put("summary", safe(proposed.summary(), 1000));
          planData.put("actionCount", proposed.steps() == null ? 0 : proposed.steps().size());
          planData.putAll(provenance.eventData(Map.of()));
          emit(
              sink,
              sequence,
              "plan",
              AgentPhase.ENGAGEMENT,
              "COMPLETED",
              safe(proposed.summary(), 1000),
              planData);
        }

        AgentPhase executionPhase = phaseForPlan(proposed);
        emit(
            sink,
            sequence,
            "state",
            executionPhase,
            "VALIDATING_TOOLS",
            "正在核对当前阶段所需工具、参数、端口与资源配额",
            Map.of());
        AiAuthorizationGuard.GuardDecision decision = guard.evaluate(request, proposed);
        Map<String, Object> guardData = new LinkedHashMap<>();
        guardData.put("plan", decision.normalizedPlan());
        guardData.put("activeProjectTasks", decision.activeProjectTasks());
        guardData.put("activeTargetTasks", decision.activeTargetTasks());
        emit(
            sink,
            sequence,
            "guard",
            executionPhase,
            decision.status(),
            decision.reason(),
            guardData);
        emit(
            sink,
            sequence,
            "approval",
            AgentPhase.VALIDATION,
            decision.approvalStatus(),
            approvalMessage(decision.approvalStatus()),
            Map.of("executionRequested", request.executionRequested()));

        List<Long> taskIds = List.of();
        boolean executed = false;
        if (decision.mayExecute() && !decision.normalizedPlan().steps().isEmpty()) {
          emit(sink, sequence, "state", executionPhase, "RUNNING", "当前红队阶段正在派发受控检测与验证任务", Map.of());
          AiDispatchResponse dispatch;
          try {
            // Tool implementation re-enters AuthorizationGuard immediately before
            // task creation to protect against authorization/quotas changing in flight.
            CrossTurnRecoveryService.RecoveryAnchor recoveryAnchor =
                recoveryAnchor(request, session.id(), provenance);
            dispatch =
                recoveryAnchor == null
                    ? tools.executeAuthorizedPlan(request, decision.normalizedPlan())
                    : tools.executeAuthorizedPlan(
                        request, decision.normalizedPlan(), recoveryAnchor);
          } catch (ApiException ex) {
            throw ex;
          } catch (Exception ex) {
            throw new ApiException("AI 工作流调用受控任务服务失败");
          }
          taskIds = dispatch.taskIds();
          executed = true;
          executionState.markDispatched(taskIds);
          for (Long taskId : taskIds) {
            emit(
                sink,
                sequence,
                "tool_call",
                executionPhase,
                "ACCEPTED",
                "受控检测任务已进入执行队列",
                Map.of("taskId", taskId));
          }
          emit(
              sink,
              sequence,
              "state",
              executionPhase,
              "COMPLETED",
              "当前阶段已创建 " + taskIds.size() + " 个受控任务",
              Map.of("taskIds", taskIds));
        } else {
          emit(
              sink,
              sequence,
              "state",
              executionPhase,
              "SKIPPED",
              decision.normalizedPlan().steps().isEmpty() ? "当前行动方案不需要调用检测工具" : "等待执行确认，尚未创建任务",
              Map.of());
        }

        emit(sink, sequence, "state", AgentPhase.RETEST, "RUNNING", "正在核对执行证据、失败原因和复测条件", Map.of());
        AiAgentResponse.AgentReview review =
            reviewer.review(request.projectId(), request.targetId(), taskIds);
        emit(
            sink,
            sequence,
            "review",
            AgentPhase.REPORTING,
            review.status(),
            review.summary(),
            Map.of("taskIds", review.verifiedTaskIds()));
        emit(
            sink,
            sequence,
            "retry",
            AgentPhase.RETEST,
            review.retryAllowed() ? "MANUAL_RETRY_AVAILABLE" : "NOT_REQUIRED",
            review.retryAllowed() ? "存在可重试任务；重试必须重新经过当前授权与配额校验" : "本轮无需重试，且智能体不会自动重复执行",
            Map.of("automaticRetry", false));

        String message = finalMessage(decision, taskIds, runtimeAnswer);
        memory.addAssistant(session.id(), message);
        AiAgentResponse response =
            new AiAgentResponse(
                session.id(),
                request.projectId(),
                request.targetId(),
                message,
                decision.normalizedPlan(),
                decision.status(),
                decision.approvalStatus(),
                executed,
                taskIds,
                review,
                memory.messageCount(session.id()),
                Instant.now());
        emit(
            sink,
            sequence,
            "done",
            AgentPhase.COMPLETED,
            "COMPLETED",
            message,
            provenance.eventData(Map.of("response", response)));
        audit.recordStructured(
            "AI_AGENT_TURN",
            "PROJECT",
            request.projectId(),
            auditDetail(request, session.id(), executed, taskIds, provenance),
            "SUCCESS");
        return response;
      } catch (RuntimeException ex) {
        try {
          emit(
              sink,
              sequence,
              "error",
              AgentPhase.ERROR,
              "FAILED",
              executionState.executed
                  ? "受控任务已经创建，但后续处理失败；请先在任务中心核对，不要创建新 Turn 重试"
                  : safeError(ex),
              Map.of(
                  "retry",
                  executionState.executed
                      ? "DO_NOT_RETRY_CHECK_TASK_CENTER"
                      : "MANUAL_AFTER_CORRECTION",
                  "executed",
                  executionState.executed,
                  "taskIds",
                  executionState.taskIds));
        } catch (RuntimeException sinkFailure) {
          if (sinkFailure != ex) ex.addSuppressed(sinkFailure);
        }
        try {
          audit.recordStructured(
              "AI_AGENT_TURN",
              "PROJECT",
              request.projectId(),
              auditDetail(
                  request,
                  session.id(),
                  executionState.executed,
                  executionState.taskIds,
                  provenance,
                  safe(ex.getMessage(), 500)),
              "FAILED");
        } catch (RuntimeException auditFailure) {
          if (auditFailure != ex) ex.addSuppressed(auditFailure);
        }
        if (executionState.executed) {
          ApiException postDispatchFailure =
              new ApiException(
                  "受控任务已经创建，但后续处理失败；请先在任务中心核对，不要创建新 Turn 重试");
          postDispatchFailure.addSuppressed(ex);
          throw postDispatchFailure;
        }
        throw ex;
      }
    }
  }

  /**
   * Complete a non-execution turn without invoking authorization, dispatch, reviewer or retry
   * machinery. Keeping this branch explicit prevents a conversational answer from accidentally
   * looking like a queued security task in the UI and audit trail.
   */
  private AiAgentResponse completeInformationalTurn(
      AiAgentRequest request,
      AiConversationMemoryService.SessionHandle session,
      Consumer<AiAgentEvent> sink,
      EventSequence sequence,
      AiPlanResponse plan,
      String answer,
      TurnProvenance provenance) {
    String message = answer == null || answer.isBlank() ? "我已理解你的问题，本轮不需要执行检测工具。" : answer;
    memory.addAssistant(session.id(), message);
    AiAgentResponse.AgentReview review =
        new AiAgentResponse.AgentReview("NOT_REQUIRED", "本轮为说明或问答，没有执行安全检测工具", false, List.of());
    AiAgentResponse response =
        new AiAgentResponse(
            session.id(),
            request.projectId(),
            request.targetId(),
            message,
            plan,
            "NOT_APPLICABLE",
            "NOT_REQUIRED",
            false,
            List.of(),
            review,
            memory.messageCount(session.id()),
            Instant.now());
    emit(
        sink,
        sequence,
        "done",
        AgentPhase.COMPLETED,
        "COMPLETED",
        message,
        provenance.eventData(
            Map.of("response", response, "intent", "ANSWER", "executed", false)));
    audit.recordStructured(
        "AI_AGENT_TURN",
        "PROJECT",
        request.projectId(),
        auditDetail(request, session.id(), false, List.of(), provenance),
        "SUCCESS");
    return response;
  }

  private boolean hasSteps(AiPlanResponse plan) {
    return plan != null && plan.steps() != null && !plan.steps().isEmpty();
  }

  public boolean clearSession(String sessionId) {
    AiConversationMemoryService.SessionScope scope = memory.clear(sessionId);
    boolean cleared = scope != null;
    Map<String, Object> detail = new LinkedHashMap<>();
    detail.put("sessionId", Objects.toString(sessionId, ""));
    detail.put("cleared", cleared);
    if (scope != null) {
      detail.put("projectId", scope.projectId());
      detail.put("targetId", scope.targetId());
    }
    audit.recordStructured(
        "AI_CONVERSATION_DELETE",
        "AI_CONVERSATION",
        sessionId,
        Collections.unmodifiableMap(detail),
        cleared ? "SUCCESS" : "NOT_FOUND");
    return cleared;
  }

  private void emit(
      Consumer<AiAgentEvent> sink,
      EventSequence sequence,
      String type,
      AgentPhase phase,
      String status,
      String message,
      Map<String, Object> data) {
    Map<String, Object> safeData = sanitizePublicData(data);
    if (!sequence.workflowDigest.isBlank()) {
      safeData.putIfAbsent("workflowDigest", sequence.workflowDigest);
    }
    if (!sequence.outerNodeId.isBlank()) safeData.putIfAbsent("outerNodeId", sequence.outerNodeId);
    if (!sequence.nodeRunId.isBlank()) safeData.putIfAbsent("nodeRunId", sequence.nodeRunId);
    long stateVersion = sequence.next();
    sink.accept(
        new AiAgentEvent(
            stateVersion,
            AiAgentRuntimeClient.CONTRACT_VERSION,
            sequence.runId,
            stateVersion,
            AiAgentRuntimeClient.POLICY_REVISION,
            type,
            phase,
            status,
            safe(message, 1200),
            Instant.now(),
            Collections.unmodifiableMap(safeData)));
  }

  private String approvalMessage(String status) {
    return switch (status) {
      case "REQUIRED" -> "行动方案仅供预览；请明确确认后再进入执行阶段";
      case "CONFIRMED_BY_REQUEST" -> "本次请求已明确确认执行低风险受控任务";
      default -> "本轮不包含需要确认的工具调用";
    };
  }

  private String finalMessage(
      AiAuthorizationGuard.GuardDecision decision, List<Long> taskIds, String preferredAnswer) {
    String summary =
        preferredAnswer == null || preferredAnswer.isBlank()
            ? safe(decision.normalizedPlan().summary(), 1000)
            : safe(preferredAnswer, 4000);
    if (!taskIds.isEmpty()) {
      return summary + "\n\n已创建 " + taskIds.size() + " 个受控任务，可在任务中心查看实时进度。";
    }
    if ("REQUIRED".equals(decision.approvalStatus())) {
      return summary + "\n\n计划已经授权守卫复核，确认执行后才会创建任务。";
    }
    return summary;
  }

  private void emitRuntimeEvent(
      Consumer<AiAgentEvent> sink,
      EventSequence sequence,
      AiAgentRuntimeClient.RuntimeEvent runtimeEvent) {
    AgentPhase phase = phaseForRuntimeEvent(runtimeEvent);
    Map<String, Object> data = sanitizePublicData(runtimeEvent.data());
    data.put("runtimeEventId", runtimeEvent.eventId());
    data.put("runtimeNode", runtimeEvent.node());
    data.put("runtimeRunId", runtimeEvent.runId());
    data.put("runtimeStateVersion", runtimeEvent.stateVersion());
    data.put("runtimePolicyRevision", runtimeEvent.policyRevision());
    data.put("runtimeContractVersion", runtimeEvent.contractVersion());
    data.put("workflowDigest", runtimeEvent.workflowDigest());
    data.put("outerNodeId", runtimeEvent.outerNodeId());
    data.put("nodeRunId", runtimeEvent.nodeRunId());
    data.put("innerStep", runtimeEvent.innerStep());
    data.put("ledgerSequence", runtimeEvent.ledgerSequence());
    data.put("ledgerEntryDigest", runtimeEvent.ledgerEntryDigest());
    if (!runtimeEvent.terminationReason().isBlank()) {
      data.put("terminationReason", runtimeEvent.terminationReason());
    }
    data.put("source", "python-langgraph-runtime");
    String status = Objects.toString(runtimeEvent.data().get("status"), "RUNNING");
    emit(sink, sequence, runtimeEvent.type(), phase, status, runtimeEvent.message(), data);
  }

  private AgentPhase phaseForRuntimeEvent(AiAgentRuntimeClient.RuntimeEvent event) {
    String node = Objects.toString(event.node(), "").toLowerCase(java.util.Locale.ROOT);
    return switch (node) {
      case "engage", "engagement", "scope", "scope_confirmation", "planner" ->
          AgentPhase.ENGAGEMENT;
      case "route" -> AgentPhase.ENGAGEMENT;
      case "recon", "reconnaissance", "evidence", "rewrite", "retrieve" ->
          AgentPhase.RECONNAISSANCE;
      case "map", "mapping", "asset_mapping", "executor" -> AgentPhase.MAPPING;
      case "discovery", "vulnerability_discovery" -> AgentPhase.DISCOVERY;
      case "validate", "validation", "approval_required", "authorization_guard" ->
          AgentPhase.VALIDATION;
      case "impact", "impact_assessment" -> AgentPhase.IMPACT;
      case "retest", "retry", "remediation" -> AgentPhase.RETEST;
      case "report", "reporting", "reviewer", "finish" -> AgentPhase.REPORTING;
      default ->
          switch (event.type()) {
            case "approval_required", "authorization_guard" -> AgentPhase.VALIDATION;
            case "tool" -> AgentPhase.MAPPING;
            case "evidence", "rewrite" -> AgentPhase.RECONNAISSANCE;
            case "route" -> AgentPhase.ENGAGEMENT;
            case "retry" -> AgentPhase.RETEST;
            case "review", "finish" -> AgentPhase.REPORTING;
            case "error" -> AgentPhase.ERROR;
            default -> AgentPhase.ENGAGEMENT;
          };
    };
  }

  private static Map<String, Object> sanitizePublicData(Map<?, ?> data) {
    Map<String, Object> sanitized = new LinkedHashMap<>();
    if (data == null) return sanitized;
    data.forEach(
        (key, value) -> {
          if (key == null || value == null || isSensitivePublicKey(key.toString())) return;
          sanitized.put(key.toString(), sanitizePublicValue(value));
        });
    return sanitized;
  }

  private static Object sanitizePublicValue(Object value) {
    if (value instanceof Map<?, ?> map) return sanitizePublicData(map);
    if (value instanceof List<?> list) {
      return list.stream()
          .filter(Objects::nonNull)
          .map(AgentOrchestrator::sanitizePublicValue)
          .toList();
    }
    return value;
  }

  private static boolean isSensitivePublicKey(String key) {
    String normalized = key.toLowerCase(java.util.Locale.ROOT).replaceAll("[^a-z]", "");
    return SENSITIVE_PUBLIC_DATA_KEYS.contains(normalized);
  }

  private Map<String, Object> auditDetail(
      AiAgentRequest request,
      String sessionId,
      boolean executed,
      List<Long> taskIds,
      TurnProvenance provenance) {
    return auditDetail(request, sessionId, executed, taskIds, provenance, "");
  }

  private CrossTurnRecoveryService.RecoveryAnchor recoveryAnchor(
      AiAgentRequest request, String sessionId, TurnProvenance provenance) {
    if (provenance.runtimeRunId.isBlank()
        || request.workflowId() == null
        || request.workflowRevision() == null
        || request.workflowDigest() == null
        || request.nodeRunId() == null
        || request.outerNodeId() == null
        || provenance.ledgerSequence <= 0
        || provenance.ledgerEntryDigest.isBlank()) {
      return null;
    }
    return new CrossTurnRecoveryService.RecoveryAnchor(
        provenance.runtimeRunId,
        sessionId,
        AiAgentRuntimeClient.POLICY_REVISION,
        provenance.ledgerSequence,
        provenance.ledgerEntryDigest);
  }

  private Map<String, Object> auditDetail(
      AiAgentRequest request,
      String sessionId,
      boolean executed,
      List<Long> taskIds,
      TurnProvenance provenance,
      String error) {
    Map<String, Object> detail = new LinkedHashMap<>();
    detail.put("schemaVersion", AiAgentRuntimeClient.CONTRACT_VERSION);
    detail.put("sessionId", sessionId);
    detail.put("turnId", request.turnId());
    detail.put("projectId", request.projectId());
    detail.put("targetId", request.targetId());
    detail.put("executed", executed);
    detail.put("taskIds", taskIds == null ? List.of() : List.copyOf(taskIds));
    detail.put("fallback", provenance.fallback);
    detail.put("fallbackReason", provenance.fallbackReason);
    detail.put("retrievalRoundCount", provenance.retrievalRoundCount);
    detail.put("evidenceIds", provenance.evidenceIds);
    detail.put("indexRevision", provenance.indexRevision);
    detail.put("plannerSource", provenance.plannerSource);
    detail.put("terminationReason", provenance.terminationReason);
    detail.put("runtimeRunId", provenance.runtimeRunId);
    detail.put("workflowDigest", Objects.toString(request.workflowDigest(), ""));
    detail.put("outerNodeId", Objects.toString(request.outerNodeId(), ""));
    detail.put("nodeRunId", Objects.toString(request.nodeRunId(), ""));
    detail.put("ledgerSequence", provenance.ledgerSequence);
    detail.put("ledgerEntryDigest", provenance.ledgerEntryDigest);
    if (error != null && !error.isBlank()) detail.put("error", error);
    return Collections.unmodifiableMap(detail);
  }

  private static final class TurnProvenance {
    private boolean fallback;
    private String fallbackReason = "NONE";
    private int retrievalRoundCount;
    private List<String> evidenceIds = List.of();
    private String indexRevision = "";
    private String plannerSource = "";
    private String terminationReason = "";
    private String runtimeRunId = "";
    private long ledgerSequence;
    private String ledgerEntryDigest = "";

    private void accept(AiAgentRuntimeClient.RuntimeEvent event) {
      runtimeRunId = event.runId();
      ledgerSequence = event.ledgerSequence();
      ledgerEntryDigest = event.ledgerEntryDigest();
      if ("evidence".equals(event.type())) {
        Object round = event.data().get("round");
        Object status = event.data().get("status");
        if (!"DENIED".equals(status) && round instanceof Number number) {
          retrievalRoundCount = Math.max(retrievalRoundCount, number.intValue() + 1);
        }
        Object revision = event.data().get("indexRevision");
        if (revision instanceof String text) indexRevision = text;
      } else if ("finish".equals(event.type())) {
        Object rounds = event.data().get("retrievalRoundCount");
        if (rounds instanceof Number number) retrievalRoundCount = number.intValue();
        evidenceIds = safeStringList(event.data().get("evidenceIds"));
        Object revision = event.data().get("indexRevision");
        indexRevision = revision instanceof String text ? text : "";
        Object source = event.data().get("plannerSource");
        plannerSource = source instanceof String text ? text : "";
        Object termination = event.data().get("terminationReason");
        terminationReason = termination instanceof String text ? text : "";
      }
    }

    private void apply(AiAgentRuntimeClient.RuntimeProvenance value) {
      if (value == null) return;
      retrievalRoundCount = value.retrievalRoundCount();
      evidenceIds = value.evidenceIds();
      indexRevision = value.indexRevision();
      plannerSource = value.plannerSource();
      terminationReason = value.terminationReason();
      String normalized = plannerSource.toLowerCase(java.util.Locale.ROOT);
      if ("RAG_DISABLED".equals(terminationReason)) {
        fallback = true;
        fallbackReason = "PYTHON_RAG_DISABLED";
      } else if (normalized.contains("legacy")
          || normalized.contains("local")
          || normalized.contains("rule")) {
        fallback = true;
        fallbackReason = "PYTHON_MODEL_FALLBACK";
      }
    }

    private void markFallback(String reason) {
      fallback = true;
      fallbackReason = reason;
    }

    private void setRuntimeRunId(String value) {
      runtimeRunId = value == null ? "" : value;
    }

    private void markProtocolRejected() {
      fallback = false;
      fallbackReason = "NONE";
      plannerSource = "RUNTIME_PROTOCOL_REJECTED";
      terminationReason = "PROTOCOL_REJECTED";
    }

    private void setJavaPlannerSource(AiPlanResponse plan) {
      String provider = plan == null || plan.provider() == null ? "" : plan.provider();
      plannerSource =
          provider.toLowerCase(java.util.Locale.ROOT).contains("local-rule")
              ? "JAVA_RULE_FALLBACK"
              : "JAVA_MODEL_FALLBACK";
    }

    private Map<String, Object> eventData(Map<String, ?> base) {
      Map<String, Object> data = new LinkedHashMap<>();
      if (base != null) data.putAll(base);
      data.put("fallback", fallback);
      data.put("fallbackReason", fallbackReason);
      data.put("retrievalRoundCount", retrievalRoundCount);
      data.put("evidenceIds", evidenceIds);
      data.put("indexRevision", indexRevision);
      data.put("plannerSource", plannerSource);
      data.put("terminationReason", terminationReason);
      data.put("runtimeRunId", runtimeRunId);
      data.put("ledgerSequence", ledgerSequence);
      data.put("ledgerEntryDigest", ledgerEntryDigest);
      return Collections.unmodifiableMap(data);
    }

    private static List<String> safeStringList(Object value) {
      if (!(value instanceof List<?> list)) return List.of();
      return list.stream().filter(String.class::isInstance).map(String.class::cast).toList();
    }
  }

  private static final class EventSequence {
    private final String runId = java.util.UUID.randomUUID().toString();
    private final String workflowDigest;
    private final String outerNodeId;
    private final String nodeRunId;
    private final AtomicLong value = new AtomicLong();

    private EventSequence(AiAgentRequest request) {
      workflowDigest = Objects.toString(request.workflowDigest(), "");
      outerNodeId = Objects.toString(request.outerNodeId(), "");
      nodeRunId = Objects.toString(request.nodeRunId(), "");
    }

    private long next() {
      return value.incrementAndGet();
    }
  }

  private static final class TurnExecutionState {
    private boolean executed;
    private List<Long> taskIds = List.of();

    private void markDispatched(List<Long> value) {
      executed = true;
      taskIds = value == null ? List.of() : List.copyOf(value);
    }
  }

  private AgentPhase phaseForPlan(AiPlanResponse plan) {
    if (plan == null || plan.steps() == null || plan.steps().isEmpty())
      return AgentPhase.ENGAGEMENT;
    boolean validation =
        plan.steps().stream()
            .anyMatch(
                step ->
                    Set.of("nuclei_scan", "afrog_scan", "xray_scan", "zap_scan")
                        .contains(step.toolCode()));
    if (validation) return AgentPhase.VALIDATION;
    boolean discovery =
        plan.steps().stream()
            .anyMatch(
                step ->
                    "http_headers".equals(step.toolCode())
                        || "http_security_check".equals(step.toolCode())
                        || "tls_config".equals(step.toolCode()));
    if (discovery) return AgentPhase.DISCOVERY;
    boolean mapping =
        plan.steps().stream()
            .anyMatch(
                step ->
                    "tcp_ports".equals(step.toolCode())
                        || "nmap_service_scan".equals(step.toolCode()));
    return mapping ? AgentPhase.MAPPING : AgentPhase.RECONNAISSANCE;
  }

  private String safeError(RuntimeException ex) {
    if (ex instanceof ApiException && ex.getMessage() != null && !ex.getMessage().isBlank()) {
      return safe(ex.getMessage(), 1000);
    }
    return "AI 智能体处理失败，请检查模型服务和授权状态后重试";
  }

  private boolean isSimpleGreeting(String value) {
    String compact =
        Objects.toString(value, "")
            .replaceAll("[\\s，。！？、,.!?]+", "")
            .toLowerCase(java.util.Locale.ROOT);
    return Set.of("你好", "您好", "嗨", "hi", "hello", "hey", "谢谢", "谢谢你")
        .contains(compact);
  }

  private String safe(String value, int max) {
    if (value == null) return "";
    String clean = value.replaceAll("[\\p{Cc}&&[^\\r\\n\\t]]", "").strip();
    return clean.length() <= max ? clean : clean.substring(0, max);
  }
}
