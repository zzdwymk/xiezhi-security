package com.bachelor.toolbox.asset;

import com.bachelor.toolbox.target.TargetService;
import java.util.List;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** 目标维度的已发现子路径查询（供主动检测编排读取扫描范围）。 */
@RestController
@RequestMapping("/api/targets/{targetId}/discovered-paths")
public class DiscoveredPathController {
  private final DiscoveredPathService service;
  private final TargetService targets;
  private final com.bachelor.toolbox.project.ProjectAuthorizationService authorization;

  public DiscoveredPathController(DiscoveredPathService service, TargetService targets,
      com.bachelor.toolbox.project.ProjectAuthorizationService authorization) {
    this.service = service;
    this.targets = targets;
    this.authorization = authorization;
  }

  @GetMapping
  public List<DiscoveredPath> list(@PathVariable Long targetId) {
    // 归属校验：必须对该授权目标有访问权，否则任何人可按 targetId 枚举他人资产的已发现路径。
    targets.get(targetId);
    // Access to one shared target does not grant access to every project's evidence.
    return authorization.isAdmin() ? service.listByTarget(targetId)
        : service.listByTarget(targetId, authorization.accessibleProjectIds());
  }
}
