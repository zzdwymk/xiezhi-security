package com.bachelor.toolbox.task;

import jakarta.validation.Valid;
import java.util.List;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

@RestController
@RequestMapping("/api/tasks")
public class TaskController {
  private final TaskService service;
  private final TaskProgressEventService progressEvents;
  private final TaskControlStatusService controlStatus;

  public TaskController(
      TaskService service,
      TaskProgressEventService progressEvents,
      TaskControlStatusService controlStatus) {
    this.service = service;
    this.progressEvents = progressEvents;
    this.controlStatus = controlStatus;
  }

  @GetMapping
  public List<SecurityTask> list() {
    return service.list();
  }

  /** Current concurrency policy and scheduler load for the task control center. */
  @GetMapping("/control/status")
  public TaskControlStatus controlStatus() {
    return controlStatus.snapshot();
  }

  @GetMapping("/{id}")
  public SecurityTask get(@PathVariable Long id) {
    return service.get(id);
  }

  @PostMapping
  @ResponseStatus(HttpStatus.ACCEPTED)
  public SecurityTask create(@Valid @RequestBody CreateTaskRequest request) throws Exception {
    SecurityTask task = service.create(request);
    progressEvents.publish(task, "任务已进入本地执行队列");
    return task;
  }

  @PostMapping("/{id}/retry")
  @ResponseStatus(HttpStatus.ACCEPTED)
  public SecurityTask retry(@PathVariable Long id) {
    SecurityTask task = service.retry(id);
    progressEvents.publish(task, "重试任务已进入本地执行队列");
    return task;
  }

  @PostMapping("/{id}/cancel")
  public SecurityTask cancel(@PathVariable Long id) {
    SecurityTask task = service.cancel(id);
    progressEvents.publish(task, "任务取消请求已提交");
    return task;
  }

  @GetMapping(value = "/{id}/events", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
  public SseEmitter events(@PathVariable Long id) {
    return progressEvents.subscribe(service.get(id));
  }

  @GetMapping(value = "/events", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
  public SseEmitter allEvents() {
    return progressEvents.subscribeAll();
  }
}
