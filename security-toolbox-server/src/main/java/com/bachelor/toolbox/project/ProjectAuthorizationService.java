package com.bachelor.toolbox.project;

import com.bachelor.toolbox.common.ApiException;
import java.util.Objects;
import java.util.concurrent.Callable;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

/** Centralizes project ownership checks so service callers cannot bypass controller authorization. */
@Service
public class ProjectAuthorizationService {
  private static final String SYSTEM_USERNAME = "SYSTEM";
  private static final ThreadLocal<Integer> SYSTEM_ACCESS_DEPTH = new ThreadLocal<>();

  private final AssessmentProjectRepository projects;

  public ProjectAuthorizationService(AssessmentProjectRepository projects) {
    this.projects = projects;
  }

  public AssessmentProject requireAccess(Long projectId) {
    AssessmentProject project =
        projects.findById(projectId).orElseThrow(() -> new ApiException("评估项目不存在"));
    if (!canAccess(project)) {
      throw new ApiException("无权访问该评估项目");
    }
    return project;
  }

  public AssessmentProject requireManage(Long projectId) {
    return requireAccess(projectId);
  }

  public void requireAdmin() {
    if (!isAdmin()) {
      throw new ApiException("仅管理员可以审批项目");
    }
  }

  public boolean isAdmin() {
    if (hasSystemAccess()) {
      return true;
    }
    Authentication authentication = currentAuthentication();
    return authentication != null
        && authentication.getAuthorities().stream()
            .anyMatch(authority -> "ROLE_ADMIN".equals(authority.getAuthority()));
  }

  public String currentUsername() {
    if (hasSystemAccess()) {
      return SYSTEM_USERNAME;
    }
    Authentication authentication = currentAuthentication();
    if (authentication == null
        || authentication.getName() == null
        || authentication.getName().isBlank()) {
      throw new ApiException("请先登录后再继续操作");
    }
    return authentication.getName();
  }

  public boolean canAccess(AssessmentProject project) {
    return isAdmin() || Objects.equals(project.getOwner(), currentUsername());
  }

  /** Runs trusted background work through normal project checks without requiring an HTTP user. */
  public <T> T callWithSystemAccess(Callable<T> operation) throws Exception {
    Objects.requireNonNull(operation, "系统操作不能为空");
    Integer currentDepth = SYSTEM_ACCESS_DEPTH.get();
    int previousDepth = currentDepth == null ? 0 : currentDepth;
    SYSTEM_ACCESS_DEPTH.set(previousDepth + 1);
    try {
      return operation.call();
    } finally {
      if (previousDepth == 0) {
        SYSTEM_ACCESS_DEPTH.remove();
      } else {
        SYSTEM_ACCESS_DEPTH.set(previousDepth);
      }
    }
  }

  private boolean hasSystemAccess() {
    Integer depth = SYSTEM_ACCESS_DEPTH.get();
    return depth != null && depth > 0;
  }

  private Authentication currentAuthentication() {
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    return authentication == null
            || !authentication.isAuthenticated()
            || authentication instanceof AnonymousAuthenticationToken
        ? null
        : authentication;
  }
}
