package com.bachelor.toolbox.task;

import jakarta.validation.Valid;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/workflow-runs")
public class WorkflowRunController {
  private final WorkflowRunService service;

  public WorkflowRunController(WorkflowRunService service) {
    this.service = service;
  }

  @GetMapping
  public List<WorkflowRunDtos.Summary> list(@RequestParam Long projectId) {
    return service.list(projectId);
  }

  @GetMapping("/{id}")
  public WorkflowRunDtos.Detail get(@PathVariable Long id) {
    return service.get(id);
  }

  @PostMapping("/preflight")
  public WorkflowRunDtos.PreflightResponse preflight(
      @Valid @RequestBody WorkflowRunDtos.SnapshotRequest request) {
    return service.preflight(request);
  }

  @PostMapping
  @ResponseStatus(HttpStatus.ACCEPTED)
  public WorkflowRunDtos.Detail start(@Valid @RequestBody WorkflowRunDtos.StartRequest request)
      throws Exception {
    return service.start(request);
  }

  @ExceptionHandler(WorkflowPreflightChangedException.class)
  public ResponseEntity<Map<String, Object>> preflightChanged(WorkflowPreflightChangedException ex) {
    return ResponseEntity.status(HttpStatus.CONFLICT).body(Map.of(
        "timestamp", Instant.now(),
        "status", HttpStatus.CONFLICT.value(),
        "code", "WORKFLOW_PREFLIGHT_CHANGED",
        "message", ex.getMessage(),
        "retryable", true,
        "requiresPreflight", true,
        "currentPreflight", ex.currentPreflight(),
        "rejectedSkippedNodeIds", ex.rejectedSkippedNodeIds()));
  }

  @PostMapping("/{id}/stop")
  public WorkflowRunDtos.Detail stop(@PathVariable Long id) {
    return service.stop(id);
  }

  @DeleteMapping("/{id}")
  @ResponseStatus(HttpStatus.NO_CONTENT)
  public void clear(@PathVariable Long id) {
    service.clear(id);
  }
}
