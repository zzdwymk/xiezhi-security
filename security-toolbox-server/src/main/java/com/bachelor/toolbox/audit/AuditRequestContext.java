package com.bachelor.toolbox.audit;

/**
 * Request-scoped audit metadata. Kept package-private to prevent business code from mutating it.
 */
final class AuditRequestContext {
  private static final ThreadLocal<RequestMetadata> CURRENT = new ThreadLocal<>();

  private AuditRequestContext() {}

  static void set(String requestId, String sourceIp) {
    CURRENT.set(new RequestMetadata(requestId, sourceIp));
  }

  static RequestMetadata get() {
    return CURRENT.get();
  }

  static void clear() {
    CURRENT.remove();
  }

  record RequestMetadata(String requestId, String sourceIp) {}
}
