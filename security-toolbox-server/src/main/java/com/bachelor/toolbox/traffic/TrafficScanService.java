package com.bachelor.toolbox.traffic;

import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.dependency.DependencyDetectionService;
import com.bachelor.toolbox.dependency.SystemDependenciesResponse;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.AuthorizedTargetRepository;
import com.bachelor.toolbox.target.PortRangeParser;
import com.bachelor.toolbox.target.TargetPolicyService;
import com.bachelor.toolbox.target.TargetService;
import com.bachelor.toolbox.target.WebTargetResolver;
import com.bachelor.toolbox.tool.FindingDraft;
import com.bachelor.toolbox.tool.ToolExecutionResult;
import com.bachelor.toolbox.tool.XrayScanTool;
import com.bachelor.toolbox.tool.zap.ZapDaemon;
import com.bachelor.toolbox.tool.zap.ZapDaemonSupplier;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class TrafficScanService {
  private static final Logger LOGGER = LoggerFactory.getLogger(TrafficScanService.class);
  private static final Duration PROBE_TIMEOUT = Duration.ofSeconds(8);

  public record TargetedScanHit(
      String title,
      String severity,
      String description,
      String parameter,
      String evidence,
      String solution) {}

  public record TargetedScanResult(
      Long packetId,
      String engine,
      String status,
      List<TargetedScanHit> hits,
      String message) {}

  public record ZapScanRequest(String strength, String policy) {}
  public record XrayScanRequest(List<String> pocCodes, boolean allPocs) {}

  private final TrafficPacketRepository packets;
  private final TargetService targets;
  private final TargetPolicyService policy;
  private final AuthorizedTargetRepository targetRepository;
  private final ZapDaemonSupplier zapDaemonSupplier;
  private final DependencyDetectionService dependencies;
  private final XrayScanTool xrayTool;
  private final AuditService audit;
  private final PortRangeParser portRangeParser;
  private final HttpClient httpClient;

  @Autowired
  public TrafficScanService(
      TrafficPacketRepository packets,
      TargetService targets,
      TargetPolicyService policy,
      AuthorizedTargetRepository targetRepository,
      @Autowired(required = false) ZapDaemonSupplier zapDaemonSupplier,
      DependencyDetectionService dependencies,
      XrayScanTool xrayTool,
      AuditService audit,
      PortRangeParser portRangeParser) {
    this.packets = packets;
    this.targets = targets;
    this.policy = policy;
    this.targetRepository = targetRepository;
    this.zapDaemonSupplier = zapDaemonSupplier;
    this.dependencies = dependencies;
    this.xrayTool = xrayTool;
    this.audit = audit;
    this.portRangeParser = portRangeParser;
    this.httpClient =
        HttpClient.newBuilder()
            .connectTimeout(PROBE_TIMEOUT)
            .followRedirects(HttpClient.Redirect.NEVER)
            .build();
  }

  public TargetedScanResult zapScan(Long packetId, ZapScanRequest request) {
    TrafficPacket packet =
        packets.findById(packetId).orElseThrow(() -> new ApiException("流量记录不存在"));
    AuthorizedTarget target = resolveTarget(packet);
    policy.validatedHttpUri(target);

    String targetUrl = buildUrl(packet);
    List<TargetedScanHit> hits = new ArrayList<>();
    String engine = "ZAP_ACTIVE";

    if (zapDaemonSupplier != null && zapAvailable()) {
      try (ZapDaemon daemon = zapDaemonSupplier.create()) {
        daemon.start();
        URI uri = URI.create(targetUrl);
        daemon.includeInScope(uri);
        String policyName = request != null && request.policy() != null ? request.policy() : "Default Policy";
        String ascanId = daemon.startActiveScan(uri, policyName);
        if (ascanId != null && !ascanId.isBlank()) {
          long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(45);
          while (System.nanoTime() < deadline) {
            int prog = daemon.activeScanProgress(ascanId);
            if (prog >= 100) break;
            Thread.sleep(600);
          }
          for (ZapDaemon.ZapAlert alert : daemon.alerts()) {
            if (alert != null) {
              hits.add(
                  new TargetedScanHit(
                      alert.name(),
                      alert.risk(),
                      alert.description(),
                      alert.url(),
                      "CWE-" + alert.cweId() + "; Confidence=" + alert.confidence(),
                      "请依据 OWASP 风险指南并结合业务上下文进行针对性修复与复测。"));
            }
          }
        }
      } catch (Exception ex) {
        LOGGER.warn("ZAP 守护进程执行失败，降级为定向启发式探针: {}", ex.getMessage());
      }
    }

    if (hits.isEmpty()) {
      engine = "ZAP_HEURISTIC";
      hits.addAll(runHeuristicProbes(packet, targetUrl));
    }

    audit.record("TRAFFIC_ZAP_SCAN", "TRAFFIC_PACKET", packetId, "hits=" + hits.size(), "SUCCESS");
    return new TargetedScanResult(
        packetId,
        engine,
        "COMPLETED",
        hits,
        hits.isEmpty()
            ? "ZAP 定向检测完成，未发现高危注入漏洞"
            : "ZAP 定向检测完成，发现 " + hits.size() + " 项潜在风险");
  }

  public TargetedScanResult xrayScan(Long packetId, XrayScanRequest request) {
    TrafficPacket packet =
        packets.findById(packetId).orElseThrow(() -> new ApiException("流量记录不存在"));
    AuthorizedTarget target = resolveTarget(packet);
    policy.validatedHttpUri(target);

    List<TargetedScanHit> hits = new ArrayList<>();
    try {
      Map<String, Object> params = new java.util.HashMap<>();
      String url = buildUrl(packet);
      if (url != null && !url.isBlank()) {
        params.put(WebTargetResolver.PARAM_RESOLVED_BASES, List.of(url));
      }
      if (request != null && request.allPocs()) {
        params.put("allPocs", true);
      } else if (request != null && request.pocCodes() != null && !request.pocCodes().isEmpty()) {
        params.put("pocCodes", request.pocCodes());
      } else {
        params.put("allPocs", true);
      }

      ToolExecutionResult result = xrayTool.execute(target, params);
      if (result != null && result.findings() != null) {
        for (FindingDraft draft : result.findings()) {
          hits.add(
              new TargetedScanHit(
                  draft.title(),
                  draft.severity(),
                  draft.description(),
                  draft.vulnerabilityCode(),
                  draft.evidence(),
                  draft.remediation()));
        }
      }
    } catch (Exception ex) {
      LOGGER.error("Xray 靶向测试失败，流量 ID={}", packetId, ex);
      throw new ApiException("Xray 靶向测试执行失败: " + ex.getMessage());
    }

    audit.record("TRAFFIC_XRAY_SCAN", "TRAFFIC_PACKET", packetId, "hits=" + hits.size(), "SUCCESS");
    return new TargetedScanResult(
        packetId,
        "XRAY_POC",
        "COMPLETED",
        hits,
        hits.isEmpty()
            ? "Xray 靶向 PoC 探测完成，未命中已选组件漏洞"
            : "Xray 靶向探测完成，命中 " + hits.size() + " 项漏洞");
  }

  private List<TargetedScanHit> runHeuristicProbes(TrafficPacket packet, String targetUrl) {
    List<TargetedScanHit> hits = new ArrayList<>();
    if (targetUrl == null || !targetUrl.startsWith("http")) return hits;

    // 1. 测试 SQL 注入字符报错与回显
    if (targetUrl.contains("=")) {
      try {
        String testUrl = targetUrl + "'";
        HttpRequest probeReq = HttpRequest.newBuilder(URI.create(testUrl)).timeout(PROBE_TIMEOUT).GET().build();
        HttpResponse<String> resp = httpClient.send(probeReq, HttpResponse.BodyHandlers.ofString());
        String body = resp.body() == null ? "" : resp.body().toLowerCase();
        if (body.contains("sql syntax") || body.contains("ora-") || body.contains("sqlite3::") || body.contains("syntax error in string")) {
          hits.add(
              new TargetedScanHit(
                  "SQL 注入（语法报错特征）",
                  "HIGH",
                  "向 URL 参数注入单引号后，服务端返回明确的数据库语法报错信息，表明参数未正确参数化。",
                  "URL Query",
                  "URL: " + testUrl + " 触发 SQL 报错",
                  "使用预编译语句（PreparedStatement）或 ORM 框架参数化查询。"));
        }
      } catch (Exception ignored) {}

      // 2. 测试 XSS 反射回显探针
      try {
        String xssProbe = "stb_zap_probe_xss<script>alert(1)</script>";
        String testUrl = targetUrl + (targetUrl.contains("?") ? "&" : "?") + "stb_test=" + xssProbe;
        HttpRequest probeReq = HttpRequest.newBuilder(URI.create(testUrl)).timeout(PROBE_TIMEOUT).GET().build();
        HttpResponse<String> resp = httpClient.send(probeReq, HttpResponse.BodyHandlers.ofString());
        if (resp.body() != null && resp.body().contains(xssProbe)) {
          hits.add(
              new TargetedScanHit(
                  "反射型跨站脚本 (Reflected XSS)",
                  "MEDIUM",
                  "输入探针未经 HTML 实体编码或过滤直接反射在响应报文体中。",
                  "stb_test",
                  "响应体包含未经转义的 Payload: " + xssProbe,
                  "对用户输入在输出到 HTML 页面前做上下文相关的转义过滤（如 HtmlUtils.htmlEscape）。"));
        }
      } catch (Exception ignored) {}
    }

    // 3. 检查敏感路径穿越与泄露
    try {
      String base = targetUrl.split("\\?")[0];
      if (base.endsWith("/")) base = base.substring(0, base.length() - 1);
      String traversalUrl = base + "/../../../../etc/passwd";
      HttpRequest probeReq = HttpRequest.newBuilder(URI.create(traversalUrl)).timeout(PROBE_TIMEOUT).GET().build();
      HttpResponse<String> resp = httpClient.send(probeReq, HttpResponse.BodyHandlers.ofString());
      if (resp.statusCode() == 200 && resp.body() != null && resp.body().contains("root:x:0:0:")) {
        hits.add(
            new TargetedScanHit(
                "路径遍历与任意文件读取",
                "HIGH",
                "利用 ../ 相对路径成功读取操作系统敏感文件 (/etc/passwd)。",
                "PATH",
                "响应状态码 200 且包含 root 用户行",
                "对路径参数使用白名单校验，过滤 ..、/、\\ 等字符。"));
      }
    } catch (Exception ignored) {}

    return hits;
  }

  private String buildUrl(TrafficPacket packet) {
    StringBuilder sb = new StringBuilder();
    sb.append(packet.getScheme() == null ? "http" : packet.getScheme()).append("://").append(packet.getHost());
    if (packet.getPort() > 0 && packet.getPort() != 80 && packet.getPort() != 443) {
      sb.append(":").append(packet.getPort());
    }
    if (packet.getPath() != null) {
      sb.append(packet.getPath());
    }
    return sb.toString();
  }

  private AuthorizedTarget resolveTarget(TrafficPacket packet) {
    int packetPort =
        packet.getPort() > 0
            ? packet.getPort()
            : ("https".equalsIgnoreCase(packet.getScheme()) ? 443 : 80);
    if (packet.getTargetId() != null && packet.getTargetId() > 0) {
      AuthorizedTarget direct = targets.get(packet.getTargetId());
      if (direct != null && direct.isEnabled() && isPortAuthorized(direct, packetPort)) {
        return direct;
      }
    }
    String host = packet.getHost();
    List<AuthorizedTarget> matches =
        targetRepository.findAll().stream()
            .filter(AuthorizedTarget::isEnabled)
            .filter(t -> t.getTargetValue() != null && isHostMatch(t.getTargetValue(), host))
            .toList();

    if (matches.isEmpty()) {
      throw new ApiException("该流量记录所属主机 [" + host + "] 未绑定授权目标，无法执行主动安全测试");
    }

    // 优先匹配包含该流量端口的目标，并按 id 倒序优先匹配最新配置
    return matches.stream()
        .sorted(java.util.Comparator.comparing(AuthorizedTarget::getId).reversed())
        .filter(t -> isPortAuthorized(t, packetPort))
        .findFirst()
        .orElseGet(() -> matches.stream().max(java.util.Comparator.comparing(AuthorizedTarget::getId)).orElse(matches.get(0)));
  }

  private boolean isPortAuthorized(AuthorizedTarget target, int port) {
    if (target == null || target.getAllowedPorts() == null || target.getAllowedPorts().isBlank()) {
      return false;
    }
    try {
      return portRangeParser.parse(target.getAllowedPorts()).contains(port);
    } catch (Exception ex) {
      return false;
    }
  }

  private boolean isHostMatch(String targetValue, String host) {
    if (targetValue == null || host == null) return false;
    if (targetValue.equalsIgnoreCase(host) || host.contains(targetValue) || targetValue.contains(host)) {
      return true;
    }
    try {
      String cleanTarget = targetValue.replaceFirst("^https?://", "").split("/")[0].split(":")[0];
      String cleanHost = host.replaceFirst("^https?://", "").split("/")[0].split(":")[0];
      return cleanTarget.equalsIgnoreCase(cleanHost);
    } catch (Exception ex) {
      return false;
    }
  }

  private boolean zapAvailable() {
    try {
      SystemDependenciesResponse response = dependencies.detect(false);
      if (response == null || response.dependencies() == null) return false;
      return response.dependencies().stream()
          .anyMatch(
              dep ->
                  dep != null
                      && "OWASP ZAP".equalsIgnoreCase(dep.name())
                      && "AVAILABLE".equalsIgnoreCase(dep.status()));
    } catch (Exception ex) {
      return false;
    }
  }
}
