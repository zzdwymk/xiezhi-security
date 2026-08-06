package com.bachelor.toolbox.task;

import java.io.IOException;
import java.time.Instant;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Service;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

@Service
public class TaskProgressEventService {
  private static final long STREAM_TIMEOUT_MS = 30L * 60L * 1000L;
  private final Map<Long, Set<SseEmitter>> subscribers = new ConcurrentHashMap<>();
  private final Set<SseEmitter> allTaskSubscribers = ConcurrentHashMap.newKeySet();
  private final Set<SseEmitter> dead = ConcurrentHashMap.newKeySet();

  public SseEmitter subscribe(SecurityTask task) {
    SseEmitter emitter = new SseEmitter(STREAM_TIMEOUT_MS);
    subscribers
        .computeIfAbsent(task.getId(), ignored -> ConcurrentHashMap.newKeySet())
        .add(emitter);
    Runnable cleanup =
        () -> {
          remove(task.getId(), emitter);
          dead.remove(emitter);
        };
    emitter.onCompletion(cleanup);
    emitter.onTimeout(cleanup);
    emitter.onError(ignored -> cleanup.run());
    send(emitter, "snapshot", payload(task, null));
    if (isTerminal(task.getStatus())) safeComplete(emitter);
    return emitter;
  }

  public SseEmitter subscribeAll() {
    SseEmitter emitter = new SseEmitter(STREAM_TIMEOUT_MS);
    allTaskSubscribers.add(emitter);
    Runnable cleanup =
        () -> {
          allTaskSubscribers.remove(emitter);
          dead.remove(emitter);
        };
    emitter.onCompletion(cleanup);
    emitter.onTimeout(cleanup);
    emitter.onError(ignored -> cleanup.run());
    send(emitter, "ready", Map.of("connected", true, "emittedAt", Instant.now().toString()));
    return emitter;
  }

  public void publish(SecurityTask task, String logLine) {
    Map<String, Object> payload = payload(task, logLine);
    Set<SseEmitter> emitters = subscribers.get(task.getId());
    if (emitters != null) {
      emitters.forEach(emitter -> send(emitter, "progress", payload));
      if (isTerminal(task.getStatus())) emitters.forEach(this::safeComplete);
    }
    allTaskSubscribers.forEach(emitter -> send(emitter, "progress", payload));
  }

  private Map<String, Object> payload(SecurityTask task, String logLine) {
    return Map.ofEntries(
        Map.entry("taskId", task.getId()),
        Map.entry("projectId", task.getProjectId() == null ? 0L : task.getProjectId()),
        Map.entry("targetId", task.getTargetId() == null ? 0L : task.getTargetId()),
        Map.entry("toolCode", task.getToolCode() == null ? "" : task.getToolCode()),
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

  private void send(SseEmitter emitter, String eventName, Object data) {
    if (dead.contains(emitter)) return;
    try {
      emitter.send(SseEmitter.event().name(eventName).data(data));
    } catch (IOException | RuntimeException ex) {
      // The socket is gone, or the async context already errored (Tomcat fired
      // AsyncListener.onError and returned). Calling complete()/completeWithError() here
      // would re-enter that torn-down AsyncContext and re-throw the
      // "non-container thread used AsyncContext after error" IllegalStateException, which
      // would escape into whatever thread called publish() — including Tomcat request
      // threads (task create/retry/cancel), surfacing as an HTTP 500. Just retire it.
      retire(emitter);
    }
  }

  private void retire(SseEmitter emitter) {
    if (!dead.add(emitter)) return;
    subscribers.values().forEach(values -> values.remove(emitter));
    allTaskSubscribers.remove(emitter);
  }

  private void safeComplete(SseEmitter emitter) {
    if (dead.contains(emitter)) return;
    try {
      emitter.complete();
    } catch (RuntimeException ex) {
      retire(emitter);
    }
  }

  private void remove(Long taskId, SseEmitter emitter) {
    Set<SseEmitter> emitters = subscribers.get(taskId);
    if (emitters == null) return;
    emitters.remove(emitter);
    if (emitters.isEmpty()) subscribers.remove(taskId, emitters);
  }

  private boolean isTerminal(String status) {
    return "SUCCESS".equals(status)
        || "FAILED".equals(status)
        || "CANCELLED".equals(status)
        || "TIMEOUT".equals(status)
        || "REJECTED".equals(status);
  }
}
