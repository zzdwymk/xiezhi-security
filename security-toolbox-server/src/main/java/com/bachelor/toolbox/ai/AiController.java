package com.bachelor.toolbox.ai;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.validation.Valid;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Objects;
import com.bachelor.toolbox.project.ProjectAuthorizationService;
import org.springframework.http.CacheControl;import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.method.annotation.StreamingResponseBody;

@RestController
@RequestMapping("/api/ai")
public class AiController {
  private final AiPlanningService service;
  private final AiTaskDispatchService dispatchService;
  private final AiDispatchStreamingService streamingService;
  private final AiAnswerService answerService;
  private final AgentOrchestrator agentOrchestrator;
  private final AiAgentRuntimeClient runtimeClient;
  private final AgentWorkflowSpecService workflowSpecs;
  private final AiWorkflowSuggestService workflowSuggestService;
  private final ObjectMapper objectMapper;
  private final ProjectAuthorizationService authorization;

  public AiController(
      AiPlanningService service,
      AiTaskDispatchService dispatchService,
      AiDispatchStreamingService streamingService,
      AiAnswerService answerService,
      AgentOrchestrator agentOrchestrator,
      AiAgentRuntimeClient runtimeClient,
      AgentWorkflowSpecService workflowSpecs,
      AiWorkflowSuggestService workflowSuggestService,
      ObjectMapper objectMapper,
      ProjectAuthorizationService authorization) {
    this.service = service;
    this.dispatchService = dispatchService;
    this.streamingService = streamingService;
    this.answerService = answerService;
    this.agentOrchestrator = agentOrchestrator;
    this.runtimeClient = runtimeClient;
    this.workflowSpecs = workflowSpecs;
    this.workflowSuggestService = workflowSuggestService;
    this.objectMapper = objectMapper;
    this.authorization = authorization;
  }
  /** Workflow topology (nodes/edges) for the visual workflow view. */
  @GetMapping("/agent/graph")
  public Object agentGraph() {
    return runtimeClient.graph();
  }

  /** Read the user-composed workflow spec (ordered tool pipeline). */
  @GetMapping("/workflow")
  public Object getWorkflow() {
    return workflowSpecs.read();
  }

  /**
   * Save the user-composed workflow spec. V2 graph documents are validated as a start-to-end DAG
   * and their executable steps are topologically grouped for safe sequential/parallel execution.
   * Legacy steps-only documents remain supported.
   */
  @PutMapping("/workflow")
  public Object saveWorkflow(@RequestBody Map<String, Object> body) {
    return workflowSpecs.save(body);
  }

  /** Real-time coaching tips for the visual workflow editor (SSE). */
  @PostMapping(value = "/workflow/suggest", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
  public ResponseEntity<StreamingResponseBody> suggestWorkflow(
      @RequestBody(required = false) Map<String, Object> body) {
    Map<String, Object> payload = body == null ? Map.of() : body;
    StreamingResponseBody stream =
        output -> {
          try {
            workflowSuggestService.stream(
                payload,
                event -> {
                  try {
                    String type = Objects.toString(event.get("type"), "message");
                    output.write(("event: " + type + "\n").getBytes(StandardCharsets.UTF_8));
                    output.write(
                        ("data: " + objectMapper.writeValueAsString(event) + "\n\n")
                            .getBytes(StandardCharsets.UTF_8));
                    output.flush();
                  } catch (java.io.IOException ex) {
                    throw new UncheckedIOException(ex);
                  }
                });
          } catch (RuntimeException ex) {
            try {
              Map<String, Object> error = new java.util.LinkedHashMap<>();
              error.put("type", "error");
              error.put("message", "工作流建议流中断");
              output.write("event: error\n".getBytes(StandardCharsets.UTF_8));
              output.write(
                  ("data: " + objectMapper.writeValueAsString(error) + "\n\n")
                      .getBytes(StandardCharsets.UTF_8));
              output.flush();
            } catch (java.io.IOException ignored) {
              // client gone
            }
          }
        };
    return ResponseEntity.ok()
        .contentType(MediaType.TEXT_EVENT_STREAM)
        .cacheControl(CacheControl.noCache())
        .header("X-Accel-Buffering", "no")
        .body(stream);
  }

  /** Save a conversation summary as retrievable project memory (LlamaIndex). */
  @PostMapping("/memories")
  public Map<String, Object> saveMemory(@RequestBody Map<String, Object> body) {
    long projectId =
        body.get("projectId") == null ? 0 : Long.parseLong(String.valueOf(body.get("projectId")));
    if (projectId <= 0) throw new com.bachelor.toolbox.common.ApiException("缺少有效的项目编号");
    authorization.requireAccess(projectId);
    String prompt = body.get("prompt") == null ? "" : String.valueOf(body.get("prompt")).strip();    String answer = body.get("answer") == null ? "" : String.valueOf(body.get("answer")).strip();
    if (prompt.isBlank() && answer.isBlank())
      throw new com.bachelor.toolbox.common.ApiException("对话内容为空，无法生成摘要");
    String conversationId =
        body.get("conversationId") == null ? "" : String.valueOf(body.get("conversationId"));
    String title =
        prompt.isBlank() ? "对话记录" : (prompt.length() > 40 ? prompt.substring(0, 40) + "…" : prompt);
    String summary = "【问题】" + clip(prompt, 800) + "\n【结论】" + clip(answer, 1600);
    String id = "conv-" + java.util.UUID.randomUUID().toString().substring(0, 12);
    String createdAt = java.time.Instant.now().toString();
    runtimeClient.appendMemory(projectId, id, title, summary, conversationId, createdAt);
    return Map.of("id", id, "title", title);
  }

  @GetMapping("/memories")
  public Object listMemories(@RequestParam long projectId) {
    authorization.requireAccess(projectId);
    return runtimeClient.listMemories(projectId);
  }
  @DeleteMapping("/memories/{docId}")
  public Map<String, Object> deleteMemory(
      @PathVariable String docId, @RequestParam long projectId) {
    authorization.requireAccess(projectId);
    return Map.of("deleted", runtimeClient.deleteMemory(projectId, docId));
  }
  private String clip(String value, int max) {
    if (value == null) return "";
    return value.length() <= max ? value : value.substring(0, max);
  }

  @DeleteMapping("/memories")
  public Map<String, Object> clearMemories(@RequestParam long projectId) {
    authorization.requireAccess(projectId);
    int deleted = runtimeClient.clearMemories(projectId);    return Map.of("deleted", deleted, "projectId", projectId);
  }

  @PostMapping("/plans")
  public AiPlanResponse plan(@Valid @RequestBody AiPlanRequest request) {
    return service.plan(request);
  }

  @PostMapping("/dispatches")
  @ResponseStatus(org.springframework.http.HttpStatus.ACCEPTED)
  public AiDispatchResponse dispatch(@Valid @RequestBody AiPlanRequest request) throws Exception {
    return dispatchService.dispatch(request);
  }

  @PostMapping(value = "/dispatches/stream", produces = "application/x-ndjson")
  public ResponseEntity<StreamingResponseBody> dispatchStream(
      @Valid @RequestBody AiPlanRequest request) {
    StreamingResponseBody body =
        output ->
            streamingService.stream(
                request,
                event -> {
                  try {
                    output.write(objectMapper.writeValueAsBytes(event));
                    output.write('\n');
                    output.flush();
                  } catch (java.io.IOException ex) {
                    throw new UncheckedIOException(ex);
                  }
                });
    return ResponseEntity.ok()
        .contentType(new MediaType("application", "x-ndjson", StandardCharsets.UTF_8))
        .cacheControl(CacheControl.noCache())
        .header("X-Accel-Buffering", "no")
        .body(body);
  }

  @PostMapping("/answers")
  public AiAnswerResponse answer(@Valid @RequestBody AiAnswerRequest request) {
    return answerService.answer(request);
  }

  @PostMapping("/agent")
  public AiAgentResponse agent(@Valid @RequestBody AiAgentRequest request) {
    return agentOrchestrator.run(request);
  }

  @PostMapping(value = "/agent/stream", produces = "application/x-ndjson")
  public ResponseEntity<StreamingResponseBody> agentStream(
      @Valid @RequestBody AiAgentRequest request) {
    StreamingResponseBody body =
        output -> {
          try {
            agentOrchestrator.run(
                request,
                event -> {
                  try {
                    output.write(objectMapper.writeValueAsBytes(event));
                    output.write('\n');
                    output.flush();
                  } catch (java.io.IOException ex) {
                    throw new UncheckedIOException(ex);
                  }
                });
          } catch (RuntimeException ignored) {
            // AgentOrchestrator emits a terminal error event before propagating the failure.
          }
        };
    return ResponseEntity.ok()
        .contentType(new MediaType("application", "x-ndjson", StandardCharsets.UTF_8))
        .cacheControl(CacheControl.noCache())
        .header("X-Accel-Buffering", "no")
        .body(body);
  }

  @DeleteMapping("/agent/sessions/{sessionId}")
  public Map<String, Object> clearAgentSession(@PathVariable String sessionId) {
    agentOrchestrator.clearSession(sessionId);
    return Map.of("sessionId", sessionId, "cleared", true);
  }
}
