package com.bachelor.toolbox.audit;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Map;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

@Service
public class AuditService {
  private static final Logger LOG = LoggerFactory.getLogger(AuditService.class);
  // 与 AuditLog 的列长度一致（见实体 @Column length）。超长会被截断，避免 DataIntegrityViolation（Round 30）。
  private static final int MAX_ACTION = 100;
  private static final int MAX_RESOURCE_TYPE = 50;
  private static final int MAX_RESULT = 30;
  private static final int MAX_OPERATOR = 100;
  private static final int MAX_OPERATOR_ROLES = 100;
  private static final int MAX_SOURCE_IP = 64;
  private static final int MAX_REQUEST_ID = 36;
  private static final int MAX_SNAPSHOT_HASH = 64;
  private static final ObjectMapper AUDIT_JSON = new ObjectMapper();
  private final AuditLogRepository repository;

  public AuditService(AuditLogRepository repository) {
    this.repository = repository;
  }

  private static String truncate(String value, int max) {
    if (value == null) return null;
    return value.length() <= max ? value : value.substring(0, max);
  }

  public void record(
      String action, String resourceType, Object resourceId, String detail, String result) {
    Long taskId =
        "TASK".equalsIgnoreCase(resourceType) && resourceId instanceof Number number
            ? number.longValue()
            : null;
    record(action, resourceType, resourceId, detail, result, taskId, null);
  }

  public void recordStructured(
      String action,
      String resourceType,
      Object resourceId,
      Map<String, ?> detail,
      String result) {
    try {
      record(action, resourceType, resourceId, AUDIT_JSON.writeValueAsString(detail), result);
    } catch (JsonProcessingException exception) {
      throw new IllegalArgumentException("审计详情无法序列化", exception);
    }
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
    log.setAction(truncate(action, MAX_ACTION));
    log.setResourceType(truncate(resourceType, MAX_RESOURCE_TYPE));
    log.setResourceId(resourceId == null ? null : resourceId.toString());
    log.setDetail(detail);
    log.setResult(truncate(result, MAX_RESULT));
    log.setRelatedTaskId(relatedTaskId);
    log.setAuthorizationSnapshotHash(truncate(authorizationSnapshotHash, MAX_SNAPSHOT_HASH));

    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    if (authentication != null && authentication.isAuthenticated()) {
      log.setOperator(truncate(authentication.getName(), MAX_OPERATOR));
      log.setOperatorRoles(
          truncate(
              authentication.getAuthorities().stream()
                  .map(GrantedAuthority::getAuthority)
                  .sorted()
                  .collect(Collectors.joining(",")),
              MAX_OPERATOR_ROLES));
    } else {
      log.setOperator("SYSTEM");
    }
    AuditRequestContext.RequestMetadata request = AuditRequestContext.get();
    if (request != null) {
      log.setRequestId(truncate(request.requestId(), MAX_REQUEST_ID));
      log.setSourceIp(truncate(request.sourceIp(), MAX_SOURCE_IP));
    }
    // Round 30：审计为"旁路记录"，其写入失败（如 DB 满、约束冲突）绝不应回滚/失败已完成的业务操作，
    // 也不应因超长字段抛 DataIntegrityViolation 让用户看到 500。这里 best-effort：失败仅告警，
    // 与"通知投递绝不改变已成功业务"的既有原则一致；失败会以 WARN 记入应用日志便于运维排查。
    try {
      repository.save(log);
    } catch (RuntimeException exception) {
      LOG.warn(
          "审计记录写入失败（已忽略，不影响业务操作）：action={}, resourceType={}, resourceId={}",
          action,
          resourceType,
          resourceId,
          exception);
    }
  }
}
