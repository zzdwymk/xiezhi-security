package com.bachelor.toolbox.asset;

import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.TargetPolicyService;
import java.net.URI;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * 集中记录/查询某授权目标下发现的 Web 子路径。写入前做去重与 host:端口 授权过滤（纵深防御：
 * 即便调用方给了越界 URL，也不会落库）。所有发现源（主动枚举、爬取、链接提取、代理、ZAP）都经此服务。
 */
@Service
public class DiscoveredPathService {
  private static final Logger log = LoggerFactory.getLogger(DiscoveredPathService.class);
  private static final int MAX_PATHS_PER_TARGET = 2000;

  private final DiscoveredPathRepository repository;
  private final TargetPolicyService policyService;

  public DiscoveredPathService(
      DiscoveredPathRepository repository, TargetPolicyService policyService) {
    this.repository = repository;
    this.policyService = policyService;
  }

  public List<DiscoveredPath> list(Long projectId, Long targetId) {
    return repository.findByProjectIdAndTargetIdOrderByDiscoveredAtDescIdDesc(projectId, targetId);
  }

  public List<DiscoveredPath> listByTarget(Long targetId) {
    return repository.findByTargetIdOrderByDiscoveredAtDescIdDesc(targetId);
  }

  /**
   * 记录一条发现的 URL。仅当 host 与目标一致、端口在授权范围内、且未重复时落库。返回是否新增。
   */
  @Transactional
  public boolean record(
      AuthorizedTarget target,
      Long projectId,
      String url,
      String source,
      Integer statusCode,
      Long responseBytes,
      String note) {
    if (url == null || url.isBlank() || target == null || projectId == null) {
      return false;
    }
    String normalized = url.trim();
    URI uri;
    try {
      uri = URI.create(normalized);
    } catch (RuntimeException ex) {
      return false;
    }
    String host = uri.getHost();
    if (host == null) {
      return false;
    }
    // host + 授权端口过滤（复用授权守卫；越界即静默丢弃）
    try {
      String targetHost = URI.create(baseForm(target.getTargetValue())).getHost();
      if (targetHost == null || !targetHost.equalsIgnoreCase(host)) {
        return false;
      }
      int port =
          uri.getPort() > 0
              ? uri.getPort()
              : ("https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80);
      policyService.validateAuthorizedPort(target, port);
    } catch (RuntimeException ex) {
      return false;
    }
    Long targetId = target.getId();
    if (repository.existsByProjectIdAndTargetIdAndUrl(projectId, targetId, normalized)) {
      return false;
    }
    if (repository.countByProjectIdAndTargetId(projectId, targetId) >= MAX_PATHS_PER_TARGET) {
      return false;
    }
    String path = uri.getRawPath() == null ? "/" : uri.getRawPath();
    if (uri.getRawQuery() != null) {
      path = path + "?" + uri.getRawQuery();
    }
    try {
      repository.save(
          new DiscoveredPath(
              projectId, targetId, normalized, path, "GET", source, statusCode, responseBytes,
              note));
      return true;
    } catch (RuntimeException ex) {
      log.debug("记录发现路径失败 url={} : {}", normalized, ex.getMessage());
      return false;
    }
  }

  private String baseForm(String targetValue) {
    return targetValue != null && targetValue.contains("://") ? targetValue : "//" + targetValue;
  }
}
