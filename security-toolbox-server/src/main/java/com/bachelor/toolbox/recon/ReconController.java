package com.bachelor.toolbox.recon;

import com.bachelor.toolbox.asset.DiscoveredPath;
import com.bachelor.toolbox.asset.DiscoveredPathService;
import jakarta.validation.Valid;
import java.util.List;
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
  private final ReconService service;
  private final DiscoveredPathService discoveredPaths;

  public ReconController(ReconService service, DiscoveredPathService discoveredPaths) {
    this.service = service;
    this.discoveredPaths = discoveredPaths;
  }

  @PostMapping("/collect")
  public ReconResult collect(
      @PathVariable Long projectId, @Valid @RequestBody ReconRequest request) {
    return service.collect(projectId, request);
  }

  @GetMapping("/results")
  public List<ReconResult> results(
      @PathVariable Long projectId, @RequestParam(required = false) Long targetId) {
    return targetId == null ? service.history(projectId) : service.history(projectId, targetId);
  }

  @GetMapping("/paths")
  public List<DiscoveredPath> paths(
      @PathVariable Long projectId, @RequestParam(required = false) Long targetId) {
    return targetId == null
        ? discoveredPaths.listByProject(projectId)
        : discoveredPaths.list(projectId, targetId);
  }

  @PostMapping("/icp/batch")
  public List<ReconService.IcpResult> icpBatch(
      @PathVariable Long projectId, @Valid @RequestBody ReconService.IcpBatchRequest request) {
    return service.icpBatch(projectId, request);
  }
}
