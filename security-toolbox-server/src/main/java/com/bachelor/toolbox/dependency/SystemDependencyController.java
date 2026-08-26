package com.bachelor.toolbox.dependency;

import jakarta.servlet.http.HttpServletRequest;
import java.net.InetAddress;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;
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
    SystemDependenciesResponse response = detectionService.detect(refresh);
    // 该接口在登录前（环境依赖检查页）即需可用，因此不能要求鉴权。
    // 但未认证调用方无需知道可执行文件的绝对路径——它会暴露用户目录与安装布局，
    // 故仅对已认证调用方返回完整信息，未认证时抹去 path。
    return isAuthenticated() ? response : withoutExecutablePaths(response);
  }

  @GetMapping(value = "/dependencies/stream", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
  public SseEmitter dependenciesStream(
      HttpServletRequest request,
      @RequestParam(value = "refresh", defaultValue = "false") boolean refresh) {
    requireLoopbackAccess(request, DEPENDENCY_LOCAL_ACCESS_ONLY);
    boolean authenticated = isAuthenticated();
    SseEmitter emitter = new SseEmitter(30_000L);

    detectionService.detectStreaming(
        status -> {
          try {
            SystemDependenciesResponse.DependencyStatus sanitized =
                authenticated ? status : withoutExecutablePath(status);
            emitter.send(SseEmitter.event().data(sanitized));
          } catch (Exception ignored) {
            // 连接断开时由 detectStreaming 内部继续完成检测并写缓存。
          }
        },
        allResults -> {
          try {
            emitter.send(SseEmitter.event().name("complete").data("done"));
            emitter.complete();
          } catch (Exception ignored) {
            // 连接已断开。
          }
        });

    emitter.onTimeout(emitter::complete);
    emitter.onError(e -> emitter.complete());
    return emitter;
  }

  private SystemDependenciesResponse.DependencyStatus withoutExecutablePath(
      SystemDependenciesResponse.DependencyStatus dependency) {
    return new SystemDependenciesResponse.DependencyStatus(
        dependency.name(),
        dependency.status(),
        dependency.version(),
        null,
        dependency.required(),
        dependency.category(),
        dependency.message());
  }

  /** 去除依赖项的绝对路径，保留名称、状态、版本等页面必需信息 */
  private SystemDependenciesResponse withoutExecutablePaths(SystemDependenciesResponse response) {
    List<SystemDependenciesResponse.DependencyStatus> sanitized =
        response.dependencies().stream()
            .map(
                dependency ->
                    new SystemDependenciesResponse.DependencyStatus(
                        dependency.name(),
                        dependency.status(),
                        dependency.version(),
                        null,
                        dependency.required(),
                        dependency.category(),
                        dependency.message()))
            .toList();
    return new SystemDependenciesResponse(response.os(), response.arch(), sanitized);
  }

  private boolean isAuthenticated() {
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    return authentication != null
        && authentication.isAuthenticated()
        && !(authentication instanceof AnonymousAuthenticationToken);
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
