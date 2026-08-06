package com.bachelor.toolbox.audit;

import com.bachelor.toolbox.common.PageRequests;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Sort;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/audits")
public class AuditController {
  private final AuditLogRepository repository;

  public AuditController(AuditLogRepository repository) {
    this.repository = repository;
  }

  @GetMapping
  public Page<AuditLog> list(
      @RequestParam(defaultValue = "0") int page,
      @RequestParam(defaultValue = "20") int size,
      @RequestParam(required = false) Long projectId) {
    var pageable = PageRequests.bounded(page, size, 1, 500, Sort.by(Sort.Order.desc("createdAt")));
    if (projectId != null && projectId > 0) {
      return repository.findByProjectId(projectId, projectId.toString(), pageable);
    }
    return repository.findAllByOrderByCreatedAtDesc(pageable);
  }
}
