package com.bachelor.toolbox.task;

import java.io.IOException;
import java.time.Instant;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.LongFunction;
import org.springframework.stereotype.Service;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

@Service
public class TaskProgressEventService {
  private static final long STREAM_TIMEOUT_MS = 30L * 60L * 1000L;
  private final Map<Long, Set<SseEmitter>> subscribers = new ConcurrentHashMap<>();
  private final Set<SseEmitter> allTaskSubscribers = ConcurrentHashMap.newKeySet();
  private final LongFunction<SseEmitter> emitterFactory;

  public TaskProgressEventService() {
    this(SseEmitter::new);
  }

  TaskProgressEventService(LongFunction<SseEmitter> emitterFactory) {
    this.emitterFactory = emitterFactory;
  }

  public SseEmitter subscribe(SecurityTask task) {
    SseEmitter emitter = emitterFactory.apply(STREAM_TIMEOUT_MS);
    subscribers.compute(
        task.getId(),
        (ignored, emitters) -> {
          Set<SseEmitter> current =
              emitters == null ? ConcurrentHashMap.newKeySet() : emitters;
          current.add(emitter);
          return current;
        });
    Runnable cleanup = () -> remove(task.getId(), emitter);
    emitter.onCompletion(cleanup);
    emitter.onTimeout(cleanup);
    emitter.onError(ignored -> cleanup.run());
    boolean sent = send(task.getId(), emitter, "snapshot", payload(task, null));
    if (sent && isTerminal(task.getStatus())) safeComplete(task.getId(), emitter);
    return emitter;
  }

  public SseEmitter subscribeAll() {
    SseEmitter emitter = emitterFactory.apply(STREAM_TIMEOUT_MS);
    allTaskSubscribers.add(emitter);
    Runnable cleanup = () -> allTaskSubscribers.remove(emitter);
    emitter.onCompletion(cleanup);
    emitter.onTimeout(cleanup);
    emitter.onError(ignored -> cleanup.run());
    send(null, emitter, "ready", Map.of("connected", true, "emittedAt", Instant.now().toString()));
    return emitter;
  }

  public void publish(SecurityTask task, String logLine) {
    Map<String, Object> payload = payload(task, logLine);
    Set<SseEmitter> emitters = subscribers.get(task.getId());
    if (emitters != null) {
      boolean terminal = isTerminal(task.getStatus());
      emitters.forEach(
          emitter -> {
            if (send(task.getId(), emitter, "progress", payload) && terminal) {
              safeComplete(task.getId(), emitter);
            }
          });
    }
    allTaskSubscribers.forEach(emitter -> send(null, emitter, "progress", payload));
  }

  private Map<String, Object> payload(SecurityTask task, String logLine) {
    return Map.ofEntries(
        Map.entry("taskId", task.getId()),
        Map.entry("projectId", task.getProjectId() == null ? 0L : task.getProjectId()),
        Map.entry("targetId", task.getTargetId() == null ? 0L : task.getTargetId()),
        Map.entry("toolCode", task.getToolCode() == null ? "" : task.getToolCode()),
        Map.entry(
            "workflowDigest", task.getWorkflowDigest() == null ? "" : task.getWorkflowDigest()),
        Map.entry(
            "workflowNodeId", task.getWorkflowNodeId() == null ? "" : task.getWorkflowNodeId()),
        Map.entry("nodeRunId", task.getNodeRunId() == null ? "" : task.getNodeRunId()),
        Map.entry("workflowGroup", task.getWorkflowGroup() == null ? 0 : task.getWorkflowGroup()),
        Map.entry("status", task.getStatus()),
        Map.entry("progress", task.getProgress()),
        Map.entry("progressDeterminate", Boolean.TRUE.equals(task.getProgressDeterminate())),
        Map.entry(
            "progressCompleted",
            task.getProgressCompleted() == null ? 0L : task.getProgressCompleted()),
        Map.entry("progressTotal", task.getProgressTotal() == null ? 0L : task.getProgressTotal()),
        Map.entry(
            "progressMessage", task.getProgressMessage() == null ? "" : task.getProgressMessage()),
        Map.entry(
            "progressUpdatedAt",
            task.getProgressUpdatedAt() == null ? "" : task.getProgressUpdatedAt().toString()),
        Map.entry("logLine", logLine == null ? "" : logLine),
        Map.entry("errorMessage", task.getErrorMessage() == null ? "" : task.getErrorMessage()),
        Map.entry(
            "terminationReason",
            task.getTerminationReason() == null ? "" : task.getTerminationReason()),
        Map.entry("timeoutAt", task.getTimeoutAt() == null ? "" : task.getTimeoutAt().toString()),
        Map.entry("startedAt", task.getStartedAt() == null ? "" : task.getStartedAt().toString()),
        Map.entry(
            "finishedAt", task.getFinishedAt() == null ? "" : task.getFinishedAt().toString()),
        Map.entry("emittedAt", Instant.now().toString()));
  }

  private boolean send(Long taskId, SseEmitter emitter, String eventName, Object data) {
    try {
      emitter.send(SseEmitter.event().name(eventName).data(data));
      return true;
    } catch (IOException | RuntimeException ex) {
      // The socket is gone, or the async context already errored (Tomcat fired
      // AsyncListener.onError and returned). Calling complete()/completeWithError() here
      // would re-enter that torn-down AsyncContext and re-throw the
      // "non-container thread used AsyncContext after error" IllegalStateException, which
      // would escape into whatever thread called publish() — including Tomcat request
      // threads (task create/retry/cancel), surfacing as an HTTP 500. Just retire it.
      retire(taskId, emitter);
      return false;
    }
  }

  private void retire(Long taskId, SseEmitter emitter) {
    if (taskId == null) allTaskSubscribers.remove(emitter);
    else remove(taskId, emitter);
  }

  private void safeComplete(Long taskId, SseEmitter emitter) {
    try {
      emitter.complete();
    } catch (RuntimeException ex) {
      retire(taskId, emitter);
    }
  }

  private void remove(Long taskId, SseEmitter emitter) {
    subscribers.computeIfPresent(
        taskId,
        (ignored, emitters) -> {
          emitters.remove(emitter);
          return emitters.isEmpty() ? null : emitters;
        });
  }

  private boolean isTerminal(String status) {
    return "SUCCESS".equals(status)
        || "FAILED".equals(status)
        || "CANCELLED".equals(status)
        || "TIMEOUT".equals(status)
        || "REJECTED".equals(status)
        || "SKIPPED".equals(status);
  }
}
