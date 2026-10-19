package com.bachelor.toolbox.tool;

import com.bachelor.toolbox.asset.DiscoveredPath;
import com.bachelor.toolbox.asset.DiscoveredPathService;
import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.recon.ReconRequest;
import com.bachelor.toolbox.recon.ReconResult;
import com.bachelor.toolbox.recon.ReconService;
import com.bachelor.toolbox.target.AuthorizedTarget;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Component;

/**
 * 站点链接爬取（信息收集）工具。
 *
 * <p>通过 {@link ReconService} 的 crawlSite 管道真实抓取目标首页、提取同源链接
 * （PASSIVE_LINK）并对动态端点做常见 GET 参数的疑似注入候选探测（ACTIVE_ENUM），
 * 全部落入 DiscoveredPath 资产库。这是只读的信息收集动作：不发送攻击载荷、
 * 不产生漏洞发现，因此注册为 SAFE 且无需管理员审批 —— 但仍然只能在被授权的
 * 目标 host:port 内执行（ReconService 内部有完整的授权校验与端口守卫）。
 *
 * <p>与 {@link ProjectContextRetrievalTool} 一样，必须由带项目归属的任务执行，
 * 项目边界来自持久化的任务记录，绝不来自调用参数。
 */
@Component
public class SiteCrawlTool implements SecurityTool {
  private final ReconService reconService;
  private final DiscoveredPathService discoveredPaths;

  public SiteCrawlTool(ReconService reconService, DiscoveredPathService discoveredPaths) {
    this.reconService = reconService;
    this.discoveredPaths = discoveredPaths;
  }

  @Override
  public String code() {
    return "site_crawl";
  }

  @Override
  public String displayName() {
    return "站点链接爬取与信息收集";
  }

  @Override
  public String description() {
    return "抓取授权目标首页并提取同源链接（页面源码链接提取），对发现的动态端点做常见 GET 参数的"
        + "疑似注入候选探测；全部结果登记进资产库。这是只读信息收集，不发送攻击载荷。";
  }

  @Override
  public ToolExecutionResult execute(AuthorizedTarget target, Map<String, Object> parameters) {
    throw new ApiException("站点爬取必须由带有项目归属的任务执行");
  }

  public ToolExecutionResult executeScoped(
      Long projectId, AuthorizedTarget target, Map<String, Object> parameters,
      ToolExecutionObserver observer) {
    if (projectId == null || projectId <= 0 || target == null || target.getId() == null) {
      throw new ApiException("站点爬取缺少项目或目标归属");
    }

    long knownBefore = discoveredPaths.list(projectId, target.getId()).size();

    observer.heartbeat("正在抓取目标首页并提取同源链接");
    if (observer.isCancellationRequested()) throw new ApiException("站点爬取已取消");

    ReconRequest request =
        new ReconRequest(
            target.getId(),
            /* includeHttp */ true,
            /* includeTls */ false,
            /* enumerateSubdomains */ false,
            /* subdomainWords */ null,
            /* enumeratePaths */ false, // 不做字典爆破；端点完全来自页面源码链接提取
            /* pathWords */ null,
            /* crawlSite */ true,
            /* aggregateProxyPaths */ false,
            /* activeNetworkProbe */ false,
            /* mode */ "ACTIVE",
            /* includeSameSubnet */ false,
            /* pathDictionaryId */ null,
            /* pathConcurrency */ null);
    ReconResult result = reconService.collect(projectId, request);

    if (observer.isCancellationRequested()) throw new ApiException("站点爬取已取消");
    observer.heartbeat("正在汇总本次与历史发现的端点资产");

    List<DiscoveredPath> allPaths = discoveredPaths.list(projectId, target.getId());
    List<Map<String, Object>> pathItems = new ArrayList<>();
    for (DiscoveredPath path : allPaths) {
      Map<String, Object> item = new LinkedHashMap<>();
      item.put("url", path.getUrl());
      item.put("path", path.getPath());
      item.put("source", path.getSource());
      item.put("note", path.getNote());
      pathItems.add(item);
    }

    Map<String, Object> data = new LinkedHashMap<>();
    data.put("targetId", target.getId());
    data.put("knownPathsBefore", knownBefore);
    data.put("knownPathsAfter", allPaths.size());
    data.put("newPathsThisRun", Math.max(0, allPaths.size() - knownBefore));
    data.put("paths", pathItems);
    data.put("evidence", result.getSourceEvidence());

    // 非静态且疑似动态的端点摘要，便于模型选择下一步注入验证目标
    String dynamicSummary =
        allPaths.stream()
            .map(DiscoveredPath::getPath)
            .filter(path -> path != null && !isStaticPath(path))
            .distinct()
            .limit(40)
            .collect(java.util.stream.Collectors.joining("\n"));

    String summary =
        "站点爬取完成：本次新增 "
            + Math.max(0, allPaths.size() - knownBefore)
            + " 条端点，资产库共 "
            + allPaths.size()
            + " 条已发现路径（含页面源码链接与疑似可注入参数候选）。"
            + "可从这些真实发现的端点中选择下一步检测目标。";
    return new ToolExecutionResult(summary, data, List.of());
  }

  private static boolean isStaticPath(String path) {
    String lower = path.toLowerCase(java.util.Locale.ROOT);
    return lower.endsWith(".css")
        || lower.endsWith(".js")
        || lower.endsWith(".png")
        || lower.endsWith(".jpg")
        || lower.endsWith(".jpeg")
        || lower.endsWith(".gif")
        || lower.endsWith(".ico")
        || lower.endsWith(".svg")
        || lower.endsWith(".woff")
        || lower.endsWith(".woff2")
        || lower.endsWith(".ttf")
        || lower.endsWith(".map");
  }
}
