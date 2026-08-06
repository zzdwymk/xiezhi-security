package com.bachelor.toolbox.probe;

import jakarta.validation.Valid;
import java.util.List;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/projects/{projectId}/discovery")
public class ProbeController {
  private final ProbeService service;

  public ProbeController(ProbeService service) {
    this.service = service;
  }

  @PostMapping("/probe")
  public ProbeResult probe(@PathVariable Long projectId, @Valid @RequestBody ProbeRequest request) {
    request.setProjectId(projectId);
    return service.probe(request);
  }

  @GetMapping("/results")
  public List<ProbeResult> history(
      @PathVariable Long projectId, @RequestParam(required = false) Long targetId) {
    return targetId == null ? service.history(projectId) : service.history(projectId, targetId);
  }
}
