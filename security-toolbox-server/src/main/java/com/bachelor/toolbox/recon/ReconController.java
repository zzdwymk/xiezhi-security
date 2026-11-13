package com.bachelor.toolbox.recon;

import com.bachelor.toolbox.asset.DiscoveredPath;
import com.bachelor.toolbox.asset.DiscoveredPathService;
import jakarta.validation.Valid;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/projects/{projectId}/recon")
public class ReconController {
  private static final Logger log = LoggerFactory.getLogger(ReconController.class);
  private final ReconService service;
  private final DiscoveredPathService discoveredPaths;
  private final com.bachelor.toolbox.project.ProjectAuthorizationService authorization;

  public ReconController(
      ReconService service,
      DiscoveredPathService discoveredPaths,
      com.bachelor.toolbox.project.ProjectAuthorizationService authorization) {
    this.service = service;
    this.discoveredPaths = discoveredPaths;
    this.authorization = authorization;
  }

  @PostMapping("/collect")
  public ReconResult collect(
      @PathVariable Long projectId, @Valid @RequestBody ReconRequest request) {
    // 归属校验：非该项目所有者（且非管理员）不得采集/读取该项目的信息收集数据。
    authorization.requireAccess(projectId);
    return service.collect(projectId, request);
  }

  @GetMapping("/results")
  public List<ReconResult> results(
      @PathVariable Long projectId, @RequestParam(required = false) Long targetId) {
    authorization.requireAccess(projectId);
    return targetId == null ? service.history(projectId) : service.history(projectId, targetId);
  }

  @GetMapping("/paths")
  public List<DiscoveredPath> paths(
      @PathVariable Long projectId, @RequestParam(required = false) Long targetId) {
    authorization.requireAccess(projectId);
    try {
      return targetId == null
          ? discoveredPaths.listByProject(projectId)
          : discoveredPaths.list(projectId, targetId);
    } catch (RuntimeException ex) {
      log.error("加载项目 {} 的已发现路径失败(targetId={})", projectId, targetId, ex);
      throw ex;
    }
  }

  @PostMapping("/icp/batch")
  public List<ReconService.IcpResult> icpBatch(
      @PathVariable Long projectId, @Valid @RequestBody ReconService.IcpBatchRequest request) {
    authorization.requireAccess(projectId);
    return service.icpBatch(projectId, request);
  }
}
