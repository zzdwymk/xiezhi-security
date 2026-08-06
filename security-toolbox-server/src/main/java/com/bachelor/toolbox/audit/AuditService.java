package com.bachelor.toolbox.audit;

import java.util.stream.Collectors;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

@Service
public class AuditService {
  private final AuditLogRepository repository;

  public AuditService(AuditLogRepository repository) {
    this.repository = repository;
  }

  public void record(
      String action, String resourceType, Object resourceId, String detail, String result) {
    Long taskId =
        "TASK".equalsIgnoreCase(resourceType) && resourceId instanceof Number number
            ? number.longValue()
            : null;
    record(action, resourceType, resourceId, detail, result, taskId, null);
  }

  public void record(
      String action,
      String resourceType,
      Object resourceId,
      String detail,
      String result,
      Long relatedTaskId,
      String authorizationSnapshotHash) {
    AuditLog log = new AuditLog();
    log.setAction(action);
    log.setResourceType(resourceType);
    log.setResourceId(resourceId == null ? null : resourceId.toString());
    log.setDetail(detail);
    log.setResult(result);
    log.setRelatedTaskId(relatedTaskId);
    log.setAuthorizationSnapshotHash(authorizationSnapshotHash);

    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    if (authentication != null && authentication.isAuthenticated()) {
      log.setOperator(authentication.getName());
      log.setOperatorRoles(
          authentication.getAuthorities().stream()
              .map(GrantedAuthority::getAuthority)
              .sorted()
              .collect(Collectors.joining(",")));
    } else {
      log.setOperator("SYSTEM");
    }
    AuditRequestContext.RequestMetadata request = AuditRequestContext.get();
    if (request != null) {
      log.setRequestId(request.requestId());
      log.setSourceIp(request.sourceIp());
    }
    repository.save(log);
  }
}
