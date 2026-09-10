package com.bachelor.toolbox.tool.zap;

import com.bachelor.toolbox.asset.DiscoveredPathService;
import com.bachelor.toolbox.probe.ProbeResult;
import com.bachelor.toolbox.probe.ProbeResultRepository;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.TargetPolicyService;
import com.bachelor.toolbox.tool.ToolExecutionResult;
import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * 把 ZAP 扫描产出的「爬取 URL 与识别到的技术栈」回填为资产/资源行（probe_results）。逐条执行
 * 授权边界校验，仅保留目标授权范围内（同 host + 同端口）的记录；预料外 URL 被丢弃。技术栈并入
 * technologies 字段，并在 evidence 中标注来源为 ZAP 爬虫/扫描。
 *
 * <p>同时把每个授权范围内的爬取 URL 写入 discovered_paths（source=ZAP_SPIDER），让 Web URL 资产
 * 汇入统一资产池，供资产拓扑展示与 sqlmap 等按 URL 复核时复用。
 */
@Component
public class ZapDiscoverySink {
  private static final Logger LOGGER = LoggerFactory.getLogger(ZapDiscoverySink.class);
  private static final int MAX_URLS = 200;

  private final ProbeResultRepository results;
  private final TargetPolicyService policy;
  private final DiscoveredPathService discoveredPaths;

  public ZapDiscoverySink(
      ProbeResultRepository results,
      TargetPolicyService policy,
      DiscoveredPathService discoveredPaths) {
    this.results = results;
    this.policy = policy;
    this.discoveredPaths = discoveredPaths;
  }

  public void ingest(
      Long projectId, Long targetId, AuthorizedTarget target, ToolExecutionResult result) {
    if (projectId == null || targetId == null || result == null || result.data() == null) {
      return;
    }
    try {
      Map<String, Object> data = result.data();
      List<?> rawUrls = asList(data.get("spiderUrls"));
      List<?> rawTech = asList(data.get("technologies"));
      if (rawUrls.isEmpty() && rawTech.isEmpty()) {
        return;
      }
      URI authorized = policy.validatedHttpUri(target);
      int saved = 0;
      for (Object o : rawUrls) {
        if (saved >= MAX_URLS) {
          break;
        }
        String url = o == null ? "" : String.valueOf(o);
        if (!isAuthorized(url, authorized)) {
          continue;
        }
        results.save(newProbe(projectId, targetId, url, rawTech));
        discoveredPaths.record(
            target, projectId, url, "ZAP_SPIDER", 0, 0L, "ZAP 爬虫发现");
        saved++;
      }
      // 无 URL 但识别到技术栈时，也以目标本身为锚点落一行，便于前端按目标展示指纹。
      if (saved == 0 && !rawTech.isEmpty()) {
        results.save(newProbe(projectId, targetId, target.getTargetValue(), rawTech));
      }
    } catch (Exception ex) {
      LOGGER.warn("ZAP 爬取结果回填资产失败 projectId={} targetId={}", projectId, targetId, ex);
    }
  }

  private ProbeResult newProbe(Long projectId, Long targetId, String url, List<?> tech) {
    ProbeResult row = new ProbeResult();
    row.setProjectId(projectId);
    row.setTargetId(targetId);
    row.setUrl(url);
    String joined =
        tech.stream().map(String::valueOf).distinct().limit(200).reduce((a, b) -> a + "," + b).orElse("");
    row.setTechnologies(joined);
    String evidence =
        "{\"source\":\"zap\",\"discoveredAt\":\""
            + java.time.Instant.now()
            + "\",\"technologies\":["
            + joinJson(tech)
            + "]}";
    row.setEvidence(evidence);
    return row;
  }

  private String joinJson(List<?> tech) {
    return tech.stream()
        .map(t -> "\"" + String.valueOf(t).replace("\"", "\\\"") + "\"")
        .reduce((a, b) -> a + "," + b)
        .orElse("");
  }

  private List<?> asList(Object value) {
    return value instanceof List<?> list ? list : List.of();
  }

  private boolean isAuthorized(String url, URI target) {
    if (url == null || url.isBlank()) {
      return false;
    }
    String candidate = url.startsWith("http") ? url : target.getScheme() + "://" + url;
    try {
      URI uri = URI.create(candidate);
      if (uri.getHost() == null) {
        return false;
      }
      return uri.getHost().equalsIgnoreCase(target.getHost()) && port(uri) == port(target);
    } catch (IllegalArgumentException ex) {
      return false;
    }
  }

  private int port(URI uri) {
    if (uri.getPort() > 0) {
      return uri.getPort();
    }
    return "https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80;
  }
}