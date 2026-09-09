package com.bachelor.toolbox.asset;

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

  public DiscoveredPathController(DiscoveredPathService service) {
    this.service = service;
  }

  @GetMapping
  public List<DiscoveredPath> list(@PathVariable Long targetId) {
    return service.listByTarget(targetId);
  }
}
