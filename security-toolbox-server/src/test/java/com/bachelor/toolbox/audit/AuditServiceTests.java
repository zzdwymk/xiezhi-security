package com.bachelor.toolbox.audit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

class AuditServiceTests {
  private final AuditLogRepository repository = mock(AuditLogRepository.class);
  private final AuditService service = new AuditService(repository);

  @AfterEach
  void clearContext() {
    SecurityContextHolder.clearContext();
    AuditRequestContext.clear();
  }

  @Test
  void enrichesAuditWithAuthenticatedRequestAndSnapshotContext() {
    SecurityContextHolder.getContext()
        .setAuthentication(
            new UsernamePasswordAuthenticationToken(
                "alice",
                "ignored",
                List.of(
                    new SimpleGrantedAuthority("ROLE_USER"),
                    new SimpleGrantedAuthority("ROLE_ADMIN"))));
    AuditRequestContext.set("13f57737-64c2-4e52-a762-079bcf45f03a", "127.0.0.1");

    service.record("CREATE_TASK", "TASK", 42L, "created", "SUCCESS", 42L, "abc123");

    var captor = org.mockito.ArgumentCaptor.forClass(AuditLog.class);
    verify(repository).save(captor.capture());
    AuditLog log = captor.getValue();
    assertEquals("alice", log.getOperator());
    assertEquals("ROLE_ADMIN,ROLE_USER", log.getOperatorRoles());
    assertEquals("127.0.0.1", log.getSourceIp());
    assertEquals("13f57737-64c2-4e52-a762-079bcf45f03a", log.getRequestId());
    assertEquals(42L, log.getRelatedTaskId());
    assertEquals("abc123", log.getAuthorizationSnapshotHash());
  }

  @Test
  void recordsBackgroundWorkAsSystemAndInfersTaskRelation() {
    service.record("EXECUTE_TOOL", "TASK", 9L, "nmap", "SUCCESS");

    var captor = org.mockito.ArgumentCaptor.forClass(AuditLog.class);
    verify(repository).save(captor.capture());
    AuditLog log = captor.getValue();
    assertEquals("SYSTEM", log.getOperator());
    assertEquals(9L, log.getRelatedTaskId());
    assertNull(log.getRequestId());
  }
}
