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
import com.bachelor.toolbox.tool.SqlmapScanTool;
import com.bachelor.toolbox.tool.ToolExecutionObserver;
import com.bachelor.toolbox.tool.ToolExecutionResult;
import com.bachelor.toolbox.tool.XrayScanTool;
import com.bachelor.toolbox.tool.zap.ZapDaemon;
import com.bachelor.toolbox.tool.zap.ZapDaemonSupplier;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
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

  public record TargetedScanProbe(
      String name,
      String method,
      String target,
      String payload,
      Integer statusCode,
      String responseSnippet,
      boolean triggered,
      String note) {}

  public record TargetedScanResult(
      Long packetId,
      String engine,
      String status,
      List<TargetedScanHit> hits,
      List<TargetedScanProbe> probes,
      String message) {}

  public record ZapScanRequest(String strength, String policy) {}
  public record XrayScanRequest(List<String> pocCodes, boolean allPocs) {}

  public record SqlmapScanRequest(Integer level, Integer risk, String technique, String data) {}

  /** 实时回调：扫描过程中逐条推送探针与命中，便于前端流式展示测试数据。 */
  public interface ZapScanListener {
    default void onStart(String targetUrl) {}

    default void onStatus(String message) {}

    default void onProbe(TargetedScanProbe probe) {}

    default void onHit(TargetedScanHit hit) {}

    default void onComplete(TargetedScanResult result) {}

    ZapScanListener NOOP = new ZapScanListener() {};
  }

  private final TrafficPacketRepository packets;
  private final TargetService targets;
  private final TargetPolicyService policy;
  private final AuthorizedTargetRepository targetRepository;
  private final ZapDaemonSupplier zapDaemonSupplier;
  private final DependencyDetectionService dependencies;
  private final XrayScanTool xrayTool;
  private final SqlmapScanTool sqlmapTool;
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
      SqlmapScanTool sqlmapTool,
      AuditService audit,
      PortRangeParser portRangeParser) {
    this.packets = packets;
    this.targets = targets;
    this.policy = policy;
    this.targetRepository = targetRepository;
    this.zapDaemonSupplier = zapDaemonSupplier;
    this.dependencies = dependencies;
    this.xrayTool = xrayTool;
    this.sqlmapTool = sqlmapTool;
    this.audit = audit;
    this.portRangeParser = portRangeParser;
    this.httpClient =
        HttpClient.newBuilder()
            .connectTimeout(PROBE_TIMEOUT)
            .followRedirects(HttpClient.Redirect.NEVER)
            .build();
  }

  public TargetedScanResult zapScan(Long packetId, ZapScanRequest request) {
    return zapScan(packetId, request, ZapScanListener.NOOP);
  }

  public TargetedScanResult zapScan(
      Long packetId, ZapScanRequest request, ZapScanListener listener) {
    TrafficPacket packet =
        packets.findById(packetId).orElseThrow(() -> new ApiException("流量记录不存在"));
    AuthorizedTarget target = resolveTarget(packet);
    policy.validatedHttpUri(target);

    String targetUrl = buildUrl(packet);
    List<TargetedScanHit> hits = new ArrayList<>();
    List<TargetedScanProbe> probes = new ArrayList<>();
    String engine = "ZAP_ACTIVE";
    listener.onStart(targetUrl);

    if (zapDaemonSupplier != null && zapAvailable()) {
      try (ZapDaemon daemon = zapDaemonSupplier.create()) {
        listener.onStatus("正在启动 OWASP ZAP 引擎并纳入扫描范围...");
        daemon.start();
        URI uri = URI.create(targetUrl);
        daemon.includeInScope(uri);
        String policyName = request != null && request.policy() != null ? request.policy() : "Default Policy";
        listener.onStatus("正在对目标执行主动漏洞扫描（策略 " + policyName + "）...");
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
              TargetedScanHit hit =
                  new TargetedScanHit(
                      alert.name(),
                      alert.risk(),
                      alert.description(),
                      alert.url(),
                      "CWE-" + alert.cweId() + "; Confidence=" + alert.confidence(),
                      "请依据 OWASP 风险指南并结合业务上下文进行针对性修复与复测。");
              hits.add(hit);
              listener.onHit(hit);
              TargetedScanProbe probe =
                  new TargetedScanProbe(
                      alert.name(),
                      "GET",
                      alert.url(),
                      "",
                      null,
                      "",
                      true,
                      "ZAP 主动扫描告警: risk="
                          + alert.risk()
                          + ", confidence="
                          + alert.confidence()
                          + ", CWE="
                          + alert.cweId());
              probes.add(probe);
              listener.onProbe(probe);
            }
          }
        }
      } catch (Exception ex) {
        LOGGER.warn("ZAP 守护进程执行失败，降级为定向启发式探针: {}", ex.getMessage());
      }
    }

    if (hits.isEmpty()) {
      engine = "ZAP_HEURISTIC";
      HeuristicOutcome outcome = runHeuristicProbes(packet, targetUrl, listener);
      hits.addAll(outcome.hits());
      probes.addAll(outcome.probes());
    }

    audit.record("TRAFFIC_ZAP_SCAN", "TRAFFIC_PACKET", packetId, "hits=" + hits.size(), "SUCCESS");
    TargetedScanResult result =
        new TargetedScanResult(
            packetId,
            engine,
            "COMPLETED",
            hits,
            probes,
            hits.isEmpty()
                ? "ZAP 定向检测完成，未发现高危注入漏洞"
                : "ZAP 定向检测完成，发现 " + hits.size() + " 项潜在风险");
    listener.onComplete(result);
    return result;
  }

  public TargetedScanResult xrayScan(Long packetId, XrayScanRequest request) {
    return xrayScan(packetId, request, ZapScanListener.NOOP);
  }

  public TargetedScanResult xrayScan(
      Long packetId, XrayScanRequest request, ZapScanListener listener) {
    TrafficPacket packet =
        packets.findById(packetId).orElseThrow(() -> new ApiException("流量记录不存在"));
    AuthorizedTarget target = resolveTarget(packet);
    policy.validatedHttpUri(target);

    List<TargetedScanHit> hits = java.util.Collections.synchronizedList(new ArrayList<>());
    listener.onStart(buildUrl(packet));
    listener.onStatus("正在执行 Xray 靶向 PoC 探测...");
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

      xrayTool.execute(
          target,
          params,
          observerFor(listener),
          draft -> {
            TargetedScanHit hit =
                new TargetedScanHit(
                    draft.title(),
                    draft.severity(),
                    draft.description(),
                    draft.vulnerabilityCode(),
                    draft.evidence(),
                    draft.remediation());
            hits.add(hit);
            listener.onHit(hit);
          });
    } catch (Exception ex) {
      LOGGER.error("Xray 靶向测试失败，流量 ID={}", packetId, ex);
      throw new ApiException("Xray 靶向测试执行失败: " + ex.getMessage());
    }

    audit.record("TRAFFIC_XRAY_SCAN", "TRAFFIC_PACKET", packetId, "hits=" + hits.size(), "SUCCESS");
    TargetedScanResult result =
        new TargetedScanResult(
            packetId,
            "XRAY_POC",
            "COMPLETED",
            hits,
            List.of(),
            hits.isEmpty()
                ? "Xray 靶向 PoC 探测完成，未命中已选组件漏洞"
                : "Xray 靶向探测完成，命中 " + hits.size() + " 项漏洞");
    listener.onComplete(result);
    return result;
  }

  public TargetedScanResult sqlmapScan(Long packetId, SqlmapScanRequest request) {
    return sqlmapScan(packetId, request, ZapScanListener.NOOP);
  }

  /**
   * 使用 sqlmap 对一条流量记录做 SQL 注入复核。将流量里的完整 URL（含查询参数）与可选的
   * 表单请求体（POST --data）交回受控的 sqlmap 子进程，并把 sqlmap 的逐行过程与注入命中通过
   * {@code listener} 实时转发，实现执行过程透明。默认仅探测（--batch、不导出数据），
   * 检测强度 level/risk/technique 由调用方在授权范围内显式指定。
   */
  public TargetedScanResult sqlmapScan(
      Long packetId, SqlmapScanRequest request, ZapScanListener listener) {
    TrafficPacket packet =
        packets.findById(packetId).orElseThrow(() -> new ApiException("流量记录不存在"));
    AuthorizedTarget target = resolveTarget(packet);
    policy.validatedHttpUri(target);

    String url = buildUrl(packet);
    List<TargetedScanHit> hits = new ArrayList<>();
    List<TargetedScanProbe> probes = new ArrayList<>();
    listener.onStart(url);

    Map<String, Object> params = new java.util.HashMap<>();
    params.put(WebTargetResolver.PARAM_RESOLVED_BASES, List.of(url));
    if (request != null) {
      if (request.level() != null) params.put("level", request.level());
      if (request.risk() != null) params.put("risk", request.risk());
      if (request.technique() != null && !request.technique().isBlank()) {
        params.put("technique", request.technique());
      }
      if (request.data() != null && !request.data().isBlank()) {
        params.put("data", request.data());
      }
    }

    ToolExecutionObserver observer = observerFor(listener);
    try {
      ToolExecutionResult toolResult =
          sqlmapTool.execute(
              target,
              params,
              observer,
              line -> listener.onStatus(line));
      for (com.bachelor.toolbox.tool.FindingDraft finding : toolResult.findings()) {
        TargetedScanHit hit =
            new TargetedScanHit(
                finding.title(),
                finding.severity(),
                finding.description(),
                finding.vulnerabilityCode(),
                finding.evidence(),
                finding.remediation());
        hits.add(hit);
        listener.onHit(hit);
      }
    } catch (ApiException ex) {
      throw ex;
    } catch (Exception ex) {
      LOGGER.error("sqlmap 复核失败，流量 ID={}", packetId, ex);
      throw new ApiException("sqlmap 复核执行失败: " + ex.getMessage());
    }

    audit.record("TRAFFIC_SQLMAP_SCAN", "TRAFFIC_PACKET", packetId, "url=" + url, "SUCCESS");
    TargetedScanResult result =
        new TargetedScanResult(
            packetId,
            "SQLMAP",
            "COMPLETED",
            hits,
            probes,
            hits.isEmpty()
                ? "sqlmap 复核完成，未确认 SQL 注入 (url=" + url + ")"
                : "sqlmap 复核完成，确认 " + hits.size() + " 处注入 (url=" + url + ")");
    listener.onComplete(result);
    return result;
  }

  private record HeuristicOutcome(List<TargetedScanHit> hits, List<TargetedScanProbe> probes) {}

  private HeuristicOutcome runHeuristicProbes(
      TrafficPacket packet, String targetUrl, ZapScanListener listener) {
    List<TargetedScanHit> hits = new ArrayList<>();
    List<TargetedScanProbe> probes = new ArrayList<>();
    if (targetUrl == null || !targetUrl.startsWith("http")) {
      return new HeuristicOutcome(hits, probes);
    }

    // 1. 测试 SQL 注入字符报错与回显
    if (targetUrl.contains("=")) {
      String sqlProbeUrl = targetUrl + "'";
      listener.onStatus("正在发送 SQL 注入（语法报错）探针...");
      try {
        HttpRequest probeReq =
            HttpRequest.newBuilder(URI.create(sqlProbeUrl)).timeout(PROBE_TIMEOUT).GET().build();
        HttpResponse<String> resp = httpClient.send(probeReq, HttpResponse.BodyHandlers.ofString());
        String body = resp.body() == null ? "" : resp.body();
        String lower = body.toLowerCase();
        boolean triggered =
            lower.contains("sql syntax")
                || lower.contains("ora-")
                || lower.contains("sqlite3::")
                || lower.contains("syntax error in string");
        emitProbe(
            probes,
            listener,
            new TargetedScanProbe(
                "SQL 注入（语法报错）",
                "GET",
                sqlProbeUrl,
                "'",
                resp.statusCode(),
                snippet(body),
                triggered,
                triggered ? "响应体命中数据库语法报错特征" : "响应体未出现数据库报错特征"));
        if (triggered) {
          emitHit(
              hits,
              listener,
              new TargetedScanHit(
                  "SQL 注入（语法报错特征）",
                  "HIGH",
                  "向 URL 参数注入单引号后，服务端返回明确的数据库语法报错信息，表明参数未正确参数化。",
                  "URL Query",
                  "URL: " + sqlProbeUrl + " 触发 SQL 报错",
                  "使用预编译语句（PreparedStatement）或 ORM 框架参数化查询。"));
        }
      } catch (Exception ex) {
        emitProbe(
            probes,
            listener,
            new TargetedScanProbe(
                "SQL 注入（语法报错）",
                "GET",
                sqlProbeUrl,
                "'",
                null,
                "",
                false,
                "请求失败: " + ex.getMessage()));
      }

      // 2. 测试 XSS 反射回显探针
      String xssProbe = "stb_zap_probe_xss<script>alert(1)</script>";
      String xssProbeUrl =
          targetUrl
              + (targetUrl.contains("?") ? "&" : "?")
              + "stb_test="
              + URLEncoder.encode(xssProbe, StandardCharsets.UTF_8);
      listener.onStatus("正在发送反射型 XSS 探针...");
      try {
        HttpRequest probeReq =
            HttpRequest.newBuilder(URI.create(xssProbeUrl)).timeout(PROBE_TIMEOUT).GET().build();
        HttpResponse<String> resp = httpClient.send(probeReq, HttpResponse.BodyHandlers.ofString());
        String body = resp.body() == null ? "" : resp.body();
        boolean triggered = body.contains(xssProbe);
        emitProbe(
            probes,
            listener,
            new TargetedScanProbe(
                "反射型 XSS 回显探测",
                "GET",
                xssProbeUrl,
                xssProbe,
                resp.statusCode(),
                snippet(body),
                triggered,
                triggered ? "响应体原样反射了未转义的 Payload" : "响应体未原样反射 Payload"));
        if (triggered) {
          emitHit(
              hits,
              listener,
              new TargetedScanHit(
                  "反射型跨站脚本 (Reflected XSS)",
                  "MEDIUM",
                  "输入探针未经 HTML 实体编码或过滤直接反射在响应报文体中。",
                  "stb_test",
                  "响应体包含未经转义的 Payload: " + xssProbe,
                  "对用户输入在输出到 HTML 页面前做上下文相关的转义过滤（如 HtmlUtils.htmlEscape）。"));
        }
      } catch (Exception ex) {
        emitProbe(
            probes,
            listener,
            new TargetedScanProbe(
                "反射型 XSS 回显探测",
                "GET",
                xssProbeUrl,
                xssProbe,
                null,
                "",
                false,
                "请求失败: " + ex.getMessage()));
      }
    }

    // 3. 检查敏感路径穿越与泄露
    String base = targetUrl.split("\\?")[0];
    if (base.endsWith("/")) base = base.substring(0, base.length() - 1);
    String traversalUrl = base + "/../../../../etc/passwd";
    listener.onStatus("正在发送路径遍历与任意文件读取探针...");
    try {
      HttpRequest probeReq =
          HttpRequest.newBuilder(URI.create(traversalUrl)).timeout(PROBE_TIMEOUT).GET().build();
      HttpResponse<String> resp = httpClient.send(probeReq, HttpResponse.BodyHandlers.ofString());
      String body = resp.body() == null ? "" : resp.body();
      boolean triggered = resp.statusCode() == 200 && body.contains("root:x:0:0:");
      emitProbe(
          probes,
          listener,
          new TargetedScanProbe(
              "路径遍历与任意文件读取",
              "GET",
              traversalUrl,
              "../../../../etc/passwd",
              resp.statusCode(),
              snippet(body),
              triggered,
              triggered ? "响应状态码 200 且包含 /etc/passwd 特征行" : "未读取到目标敏感文件"));
      if (triggered) {
        emitHit(
            hits,
            listener,
            new TargetedScanHit(
                "路径遍历与任意文件读取",
                "HIGH",
                "利用 ../ 相对路径成功读取操作系统敏感文件 (/etc/passwd)。",
                "PATH",
                "响应状态码 200 且包含 root 用户行",
                "对路径参数使用白名单校验，过滤 ..、/、\\ 等字符。"));
      }
    } catch (Exception ex) {
      emitProbe(
          probes,
          listener,
          new TargetedScanProbe(
              "路径遍历与任意文件读取",
              "GET",
              traversalUrl,
              "../../../../etc/passwd",
              null,
              "",
              false,
              "请求失败: " + ex.getMessage()));
    }

    return new HeuristicOutcome(hits, probes);
  }

  private static void emitProbe(
      List<TargetedScanProbe> probes, ZapScanListener listener, TargetedScanProbe probe) {
    probes.add(probe);
    listener.onProbe(probe);
  }

  private static void emitHit(
      List<TargetedScanHit> hits, ZapScanListener listener, TargetedScanHit hit) {
    hits.add(hit);
    listener.onHit(hit);
  }

  /** 把底层工具的可观察过程（命令/操作/心跳/进度）桥接为面向用户的实时状态推送，实现执行过程透明。 */
  private static ToolExecutionObserver observerFor(ZapScanListener listener) {
    return new ToolExecutionObserver() {
      @Override
      public void command(List<String> command) {
        listener.onStatus("执行命令: " + String.join(" ", command));
      }

      @Override
      public void operation(String operation) {
        if (operation != null && !operation.isBlank()) {
          listener.onStatus(operation);
        }
      }

      @Override
      public void progress(long completed, long total, String operation) {
        if (operation != null && !operation.isBlank()) {
          listener.onStatus(operation);
        }
      }

      @Override
      public void heartbeat(String operation) {
        if (operation != null && !operation.isBlank()) {
          listener.onStatus(operation);
        }
      }
    };
  }

  private static String snippet(String body) {
    if (body == null || body.isBlank()) {
      return "";
    }
    String normalized = body.replaceAll("\\s+", " ").trim();
    return normalized.length() > 400 ? normalized.substring(0, 400) + "..." : normalized;
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
