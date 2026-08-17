package com.bachelor.toolbox.dependency;

import jakarta.servlet.http.HttpServletRequest;
import java.net.InetAddress;
import java.util.Map;
import java.util.Objects;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api/system")
public class SystemDependencyController {
  private static final String DEPENDENCY_LOCAL_ACCESS_ONLY = "依赖状态仅允许从本机访问";
  private static final String HEALTH_LOCAL_ACCESS_ONLY = "健康状态仅允许从本机访问";
  private static final String SHUTDOWN_LOCAL_ACCESS_ONLY = "关机操作仅允许从本机访问";
  private static final String SHUTDOWN_INVALID_TOKEN = "关机令牌无效";

  private final DependencyDetectionService detectionService;

  public SystemDependencyController(DependencyDetectionService detectionService) {
    this.detectionService = detectionService;
  }

  @GetMapping("/dependencies")
  public SystemDependenciesResponse dependencies(
      HttpServletRequest request,
      @RequestParam(value = "refresh", defaultValue = "false") boolean refresh) {
    requireLoopbackAccess(request, DEPENDENCY_LOCAL_ACCESS_ONLY);
    return detectionService.detect(refresh);
  }

  @GetMapping("/health")
  public Map<String, String> health(HttpServletRequest request) {
    requireLoopbackAccess(request, HEALTH_LOCAL_ACCESS_ONLY);
    return Map.of("status", "UP");
  }

  @PostMapping("/shutdown")
  public Map<String, String> shutdown(
      HttpServletRequest request,
      @RequestHeader(value = "X-Shutdown-Token", required = false) String token) {
    requireLoopbackAccess(request, SHUTDOWN_LOCAL_ACCESS_ONLY);
    if (!Objects.equals(token, System.getenv("TOOLBOX_SHUTDOWN_TOKEN"))
        || System.getenv("TOOLBOX_SHUTDOWN_TOKEN") == null
        || System.getenv("TOOLBOX_SHUTDOWN_TOKEN").isEmpty()) {
      throw new ResponseStatusException(HttpStatus.FORBIDDEN, SHUTDOWN_INVALID_TOKEN);
    }
    new Thread(
            () -> {
              try {
                Thread.sleep(200);
              } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
              }
              System.exit(0);
            },
            "toolbox-shutdown")
        .start();
    return Map.of("status", "shutting-down");
  }

  private void requireLoopbackAccess(HttpServletRequest request, String errorMessage) {
    if (!isLoopback(request.getRemoteAddr())) {
      throw new ResponseStatusException(HttpStatus.FORBIDDEN, errorMessage);
    }
  }

  private boolean isLoopback(String remoteAddress) {
    try {
      return remoteAddress != null && InetAddress.getByName(remoteAddress).isLoopbackAddress();
    } catch (Exception ignored) {
      return false;
    }
  }
}
