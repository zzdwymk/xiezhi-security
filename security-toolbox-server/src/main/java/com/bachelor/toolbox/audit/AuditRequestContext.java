package com.bachelor.toolbox.audit;

import java.util.Objects;
import org.springframework.web.servlet.mvc.method.annotation.StreamingResponseBody;

/**
 * Request-scoped audit metadata. Mutators stay package-private; public wrappers only propagate
 * metadata already established by the request filter.
 */
public final class AuditRequestContext {
  private static final ThreadLocal<RequestMetadata> CURRENT = new ThreadLocal<>();

  private AuditRequestContext() {}

  /** Captures the submitting request without retaining the servlet request or changing identity. */
  public static Runnable wrap(Runnable action) {
    Objects.requireNonNull(action, "action");
    RequestMetadata captured = CURRENT.get();
    return () -> {
      RequestMetadata previous = CURRENT.get();
      restore(captured);
      try {
        action.run();
      } finally {
        restore(previous);
      }
    };
  }

  /** Propagates audit metadata to a Spring MVC stream; Spring Security handles its authentication. */
  public static StreamingResponseBody wrapStream(StreamingResponseBody stream) {
    Objects.requireNonNull(stream, "stream");
    RequestMetadata captured = CURRENT.get();
    return output -> {
      RequestMetadata previous = CURRENT.get();
      restore(captured);
      try {
        stream.writeTo(output);
      } finally {
        restore(previous);
      }
    };
  }

  private static void restore(RequestMetadata metadata) {
    if (metadata == null) CURRENT.remove();
    else CURRENT.set(metadata);
  }

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
