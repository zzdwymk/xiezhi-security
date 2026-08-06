package com.bachelor.toolbox.ai;

import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.common.ApiException;
import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;
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
  private final AiConversationMemoryService memory;
  private final SecurityAgentTools tools;
  private final AiAgentRuntimeClient runtimeClient;
  private final AiProjectIndexService projectIndex;
  private final AiPlanningService planner;
  private final AiAuthorizationGuard guard;
  private final AiExecutionReviewer reviewer;
  private final AuditService audit;

  public AgentOrchestrator(
      AiConversationMemoryService memory,
      SecurityAgentTools tools,
      AiAgentRuntimeClient runtimeClient,
      AiProjectIndexService projectIndex,
      AiPlanningService planner,
      AiAuthorizationGuard guard,
      AiExecutionReviewer reviewer,
      AuditService audit) {
    this.memory = memory;
    this.tools = tools;
    this.runtimeClient = runtimeClient;
    this.projectIndex = projectIndex;
    this.planner = planner;
    this.guard = guard;
    this.reviewer = reviewer;
    this.audit = audit;
  }

  public AiAgentResponse run(AiAgentRequest request) {
    return run(request, ignored -> {});
  }

  public AiAgentResponse run(AiAgentRequest request, Consumer<AiAgentEvent> eventSink) {
    Consumer<AiAgentEvent> sink = eventSink == null ? ignored -> {} : eventSink;
    AtomicLong sequence = new AtomicLong();
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

        String history = memory.transcript(session.id());
        memory.addUser(session.id(), request.prompt());
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
                  request.mode());
          try {
            AiAgentRuntimeClient.RuntimePlanResult runtimeResult =
                runtimeClient.plan(
                    runtimeRequest,
                    planningPrompt,
                    runtimeEvent -> emitRuntimeEvent(sink, sequence, runtimeEvent));
            proposed = runtimeResult.plan();
            runtimeAnswer = runtimeResult.answer();
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
                Map.of("runtimeStatus", runtimeResult.status()));
          } catch (AiAgentRuntimeClient.RuntimeUnavailableException ex) {
            emit(
                sink,
                sequence,
                "planner_progress",
                AgentPhase.ENGAGEMENT,
                "LOCAL_FALLBACK",
                "本地 AI Runtime 不可用，改由 Java 规划器理解意图",
                Map.of("fallback", true));
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
              answer);
        }
        {
          Map<String, Object> planData = new LinkedHashMap<>();
          planData.put("plan", proposed);
          planData.put("steps", proposed.steps() == null ? List.of() : proposed.steps());
          planData.put("summary", safe(proposed.summary(), 1000));
          planData.put("actionCount", proposed.steps() == null ? 0 : proposed.steps().size());
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
            dispatch = tools.executeAuthorizedPlan(request, decision.normalizedPlan());
          } catch (ApiException ex) {
            throw ex;
          } catch (Exception ex) {
            throw new ApiException("AI 工作流调用受控任务服务失败");
          }
          taskIds = dispatch.taskIds();
          executed = true;
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
            Map.of("response", response));
        audit.record(
            "AI_AGENT_TURN",
            "PROJECT",
            request.projectId(),
            "sessionId="
                + session.id()
                + "; targetId="
                + request.targetId()
                + "; execute="
                + executed
                + "; taskIds="
                + taskIds,
            "SUCCESS");
        return response;
      } catch (RuntimeException ex) {
        emit(
            sink,
            sequence,
            "error",
            AgentPhase.ERROR,
            "FAILED",
            safeError(ex),
            Map.of("retry", "MANUAL_AFTER_CORRECTION"));
        audit.record(
            "AI_AGENT_TURN",
            "PROJECT",
            request.projectId(),
            "sessionId="
                + session.id()
                + "; targetId="
                + request.targetId()
                + "; error="
                + safe(ex.getMessage(), 500),
            "FAILED");
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
      AtomicLong sequence,
      AiPlanResponse plan,
      String answer) {
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
        Map.of("response", response, "intent", "ANSWER", "executed", false));
    audit.record(
        "AI_AGENT_TURN",
        "PROJECT",
        request.projectId(),
        "sessionId="
            + session.id()
            + "; targetId="
            + request.targetId()
            + "; intent=ANSWER; execute=false; taskIds=[]",
        "SUCCESS");
    return response;
  }

  private boolean hasSteps(AiPlanResponse plan) {
    return plan != null && plan.steps() != null && !plan.steps().isEmpty();
  }

  public void clearSession(String sessionId) {
    memory.clear(sessionId);
  }

  private void emit(
      Consumer<AiAgentEvent> sink,
      AtomicLong sequence,
      String type,
      AgentPhase phase,
      String status,
      String message,
      Map<String, Object> data) {
    Map<String, Object> safeData = new LinkedHashMap<>();
    if (data != null)
      data.forEach(
          (key, value) -> {
            if (key != null && value != null) safeData.put(key, value);
          });
    sink.accept(
        new AiAgentEvent(
            sequence.incrementAndGet(),
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
      AtomicLong sequence,
      AiAgentRuntimeClient.RuntimeEvent runtimeEvent) {
    AgentPhase phase = phaseForRuntimeEvent(runtimeEvent);
    Map<String, Object> data = new LinkedHashMap<>(runtimeEvent.data());
    data.put("runtimeEventId", runtimeEvent.eventId());
    data.put("runtimeNode", runtimeEvent.node());
    data.put("source", "python-langgraph-runtime");
    String status = Objects.toString(runtimeEvent.data().get("status"), "RUNNING");
    emit(sink, sequence, runtimeEvent.type(), phase, status, runtimeEvent.message(), data);
  }

  private AgentPhase phaseForRuntimeEvent(AiAgentRuntimeClient.RuntimeEvent event) {
    String node = Objects.toString(event.node(), "").toLowerCase(java.util.Locale.ROOT);
    return switch (node) {
      case "engage", "engagement", "scope", "scope_confirmation", "planner" ->
          AgentPhase.ENGAGEMENT;
      case "recon", "reconnaissance" -> AgentPhase.RECONNAISSANCE;
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
            case "retry" -> AgentPhase.RETEST;
            case "review", "finish" -> AgentPhase.REPORTING;
            case "error" -> AgentPhase.ERROR;
            default -> AgentPhase.ENGAGEMENT;
          };
    };
  }

  private AgentPhase phaseForPlan(AiPlanResponse plan) {
    if (plan == null || plan.steps() == null || plan.steps().isEmpty())
      return AgentPhase.ENGAGEMENT;
    boolean validation =
        plan.steps().stream().anyMatch(step -> "nuclei_scan".equals(step.toolCode()));
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

  private String safe(String value, int max) {
    if (value == null) return "";
    String clean = value.replaceAll("[\\p{Cc}&&[^\\r\\n\\t]]", "").strip();
    return clean.length() <= max ? clean : clean.substring(0, max);
  }
}
