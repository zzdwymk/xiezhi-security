package com.bachelor.toolbox.settings;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Set;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/** Holds a shared gate for mutating API requests while an exclusive reset is not running. */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 1)
public class BusinessDataOperationFilter extends OncePerRequestFilter {
  private static final Set<String> READ_METHODS = Set.of("GET", "HEAD", "OPTIONS");
  private final BusinessDataOperationGate gate;

  public BusinessDataOperationFilter(BusinessDataOperationGate gate) {
    this.gate = gate;
  }

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {
    if (!isBusinessMutation(request)) {
      filterChain.doFilter(request, response);
      return;
    }
    try {
      gate.withMutation(
          () -> {
            try {
              filterChain.doFilter(request, response);
            } catch (ServletException | IOException exception) {
              throw new FilterFailure(exception);
            }
          });
    } catch (FilterFailure failure) {
      if (failure.getCause() instanceof ServletException servletException) {
        throw servletException;
      }
      throw (IOException) failure.getCause();
    }
  }

  private boolean isBusinessMutation(HttpServletRequest request) {
    String path = request.getServletPath();
    return path.startsWith("/api/")
        && !READ_METHODS.contains(request.getMethod())
        && !("DELETE".equals(request.getMethod()) && "/api/settings/data".equals(path));
  }

  private static final class FilterFailure extends RuntimeException {
    private FilterFailure(Exception cause) {
      super(cause);
    }
  }
}
