package com.bachelor.toolbox.operation;

import jakarta.validation.Valid;
import java.util.List;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/projects/{projectId}/security-actions")
public class SecurityActionController {
  private final SecurityActionService service;

  public SecurityActionController(SecurityActionService service) {
    this.service = service;
  }

  @GetMapping
  public List<SecurityAction> list(@PathVariable Long projectId) {
    return service.list(projectId);
  }

  @PostMapping
  public SecurityAction create(
      @PathVariable Long projectId,
      @Valid @RequestBody SecurityActionDtos.Create request,
      Authentication authentication) {
    return service.create(projectId, request, authentication);
  }

  @PostMapping("/{id}/decision")
  public SecurityAction decide(
      @PathVariable Long projectId,
      @PathVariable Long id,
      @Valid @RequestBody SecurityActionDtos.Decision request,
      Authentication authentication) {
    return service.decide(projectId, id, request, authentication);
  }

  @PostMapping("/{id}/start")
  public SecurityAction start(@PathVariable Long projectId, @PathVariable Long id) {
    return service.start(projectId, id);
  }

  @PostMapping("/{id}/complete")
  public SecurityAction complete(
      @PathVariable Long projectId,
      @PathVariable Long id,
      @Valid @RequestBody SecurityActionDtos.Complete request) {
    return service.complete(projectId, id, request);
  }

  @PostMapping("/{id}/rollback")
  public SecurityAction rollback(
      @PathVariable Long projectId,
      @PathVariable Long id,
      @Valid @RequestBody SecurityActionDtos.Rollback request) {
    return service.rollback(projectId, id, request);
  }
}
