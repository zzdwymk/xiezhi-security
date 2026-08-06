package com.bachelor.toolbox.postscan;

import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/post-scan-paths")
public class PostScanPathController {
  private final PostScanPathService service;

  public PostScanPathController(PostScanPathService service) {
    this.service = service;
  }

  @PostMapping("/plans")
  public PostScanPathResponse plan(@Valid @RequestBody PostScanPathRequest request)
      throws Exception {
    return service.plan(request);
  }

  @GetMapping("/{id}")
  public PostScanPathResponse get(@PathVariable Long id) throws Exception {
    return service.get(id);
  }

  @PostMapping("/{id}/confirm")
  @ResponseStatus(HttpStatus.ACCEPTED)
  public PostScanPathResponse confirm(
      @PathVariable Long id, @Valid @RequestBody PostScanConfirmRequest request) throws Exception {
    return service.confirm(id, request);
  }
}
