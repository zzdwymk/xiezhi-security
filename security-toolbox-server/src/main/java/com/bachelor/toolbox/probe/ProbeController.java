package com.bachelor.toolbox.probe;

import jakarta.validation.Valid;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/projects/{projectId}/discovery")
public class ProbeController {
  private static final Logger log = LoggerFactory.getLogger(ProbeController.class);
  private final ProbeService service;

  public ProbeController(ProbeService service) {
    this.service = service;
  }

  @PostMapping("/probe")
  public ProbeResult probe(@PathVariable Long projectId, @Valid @RequestBody ProbeRequest request) {
    request.setProjectId(projectId);
    return service.probe(request);
  }

  @GetMapping("/results")
  public List<ProbeResult> history(
      @PathVariable Long projectId, @RequestParam(required = false) Long targetId) {
    try {
      return targetId == null ? service.history(projectId) : service.history(projectId, targetId);
    } catch (RuntimeException ex) {
      log.error("加载项目 {} 的探针/资产探测结果失败(targetId={})", projectId, targetId, ex);
      throw ex;
    }
  }

  /** 删除一条资产/结果节点：仅限该项目内，且受项目授权与目标归属约束。 */
  @DeleteMapping("/results/{id}")
  public void delete(@PathVariable Long projectId, @PathVariable Long id) {
    service.delete(projectId, id);
  }
}
