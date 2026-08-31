package com.bachelor.toolbox.tool;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.PortRangeParser;
import com.bachelor.toolbox.target.TargetPolicyService;
import com.bachelor.toolbox.vulnerability.HostPlugin;
import com.bachelor.toolbox.vulnerability.HostPluginCatalogService;
import com.bachelor.toolbox.vulnerability.HostPluginParser;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * 内置主机漏扫引擎：在授权主机上对用户明确选择的 HOST 插件执行只读探测。
 *
 * <p>插件按声明能力拆分为两类探测，均只读且不越过授权端口：
 *
 * <ul>
 *   <li>仅端口/服务指纹：对协议对应端口做 TCP 连接 + 读回显，输出为资产观察
 *       （vulnerability=false），不臆断漏洞。
 *   <li>SAFE/需审查、且探测到 banner 的插件：仅当至少有一个授权端口可达时产出潜在问题
 *       FindingDraft（严重度不超过插件声明值）。绝不包含写入、注入或破坏性动作。
 * </ul>
 *
 * <p>任何标记 <code>exploit_available</code> 或面临 BLOCKED 扫描安全级别的插件都会被拒接，
 * 避免自动执行高影响动作。
 */
@Component
public class NativeVulnScanTool implements SecurityTool {
  private static final Logger log = LoggerFactory.getLogger(NativeVulnScanTool.class);
  private static final int MAX_FINDINGS = 500;
  private static final int MAX_PLUGINS = 50;
  private static final int MAX_BANNER_BYTES = 16 * 1024;
  private static final int CONNECT_TIMEOUT_MS = 2500;
  private static final int READ_TIMEOUT_MS = 2500;
  private static final long DEFAULT_TIMEOUT_SECONDS = 180;
  private static final Set<String> SEVERITIES =
      Set.of("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO");
  private static final Map<String, Integer> WELL_KNOWN_PORTS =
      Map.ofEntries(
          Map.entry("ssh", 22),
          Map.entry("telnet", 23),
          Map.entry("smtp", 25),
          Map.entry("http", 80),
          Map.entry("www", 80),
          Map.entry("https", 443),
          Map.entry("dns", 53),
          Map.entry("ftp", 21),
          Map.entry("rdp", 3389),
          Map.entry("smb", 445),
          Map.entry("mysql", 3306),
          Map.entry("redis", 6379),
          Map.entry("pop3", 110),
          Map.entry("imap", 143),
          Map.entry("postgres", 5432));

  private final TargetPolicyService policy;
  private final PortRangeParser portRangeParser;
  private final ScannerPocSelectionService pocSelection;
  private final HostPluginParser pluginParser;
  private final BannerProber prober;
  private final long timeoutSeconds;

  public NativeVulnScanTool(
      TargetPolicyService policy,
      PortRangeParser portRangeParser,
      ScannerPocSelectionService pocSelection,
      HostPluginParser pluginParser) {
    this(policy, portRangeParser, pocSelection, pluginParser, new SocketBannerProber(), DEFAULT_TIMEOUT_SECONDS);
  }

  public NativeVulnScanTool(
      TargetPolicyService policy,
      PortRangeParser portRangeParser,
      ScannerPocSelectionService pocSelection,
      HostPluginParser pluginParser,
      BannerProber prober,
      long timeoutSeconds) {
    this.policy = policy;
    this.portRangeParser = portRangeParser;
    this.pocSelection = pocSelection;
    this.pluginParser = pluginParser;
    this.prober = prober;
    this.timeoutSeconds = timeoutSeconds;
  }

  @Override
  public String code() {
    return "native_vuln_scan";
  }

  @Override
  public String displayName() {
    return "内置主机漏扫";
  }

  @Override
  public String description() {
    return "对授权主机上用户明确选择的内置主机插件执行只读指纹与安全检测";
  }

  @Override
  public ToolExecutionResult execute(AuthorizedTarget target, Map<String, Object> parameters)
      throws Exception {
    return execute(target, parameters, ToolExecutionObserver.NOOP);
  }

  @Override
  public ToolExecutionResult execute(
      AuthorizedTarget target, Map<String, Object> parameters, ToolExecutionObserver observer)
      throws Exception {
    String host = policy.validatedHost(target);
    Set<Integer> allowed = portRangeParser.parse(target.getAllowedPorts());

    List<ScannerPocSelectionService.SelectedPoc> selected =
        pocSelection.resolve(HostPluginCatalogService.SOURCE_TYPE, parameters, false);
    if (selected.size() > MAX_PLUGINS) {
      throw new ApiException("单次内置漏扫最多执行 " + MAX_PLUGINS + " 个插件");
    }

    List<FindingDraft> findings = new ArrayList<>();
    List<Map<String, Object>> matches = new ArrayList<>();
    List<Map<String, Object>> observations = new ArrayList<>();
    List<String> skipped = new ArrayList<>();

    long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(timeoutSeconds);
    ExecutorService pool = Executors.newFixedThreadPool(4);
    try {
      for (ScannerPocSelectionService.SelectedPoc item : selected) {
        observer.heartbeat("正在处理插件 " + item.externalId());
        HostPlugin plugin;
        try {
          plugin = readPlugin(item);
        } catch (Exception ex) {
          skipped.add(item.externalId() + ": 插件解析失败或文件缺失，" + ex.getMessage());
          continue;
        }
        if (plugin.exploitAvailable() || "BLOCKED".equalsIgnoreCase(plugin.scanSafety())) {
          skipped.add(plugin.id() + ": 含高影响或利用特征，拒绝自动执行");
          continue;
        }
        Set<Integer> probePorts = authorizedPluginPorts(plugin, allowed);
        if (probePorts.isEmpty()) {
          skipped.add(plugin.id() + ": 无授权可探测端口");
          continue;
        }
        for (int port : probePorts) {
          if (System.nanoTime() >= deadline) {
            throw new ApiException("内置漏扫超过 " + timeoutSeconds + " 秒，已终止");
          }
          ProbeResult probe;
          try {
            probe = prober.probe(host, port);
          } catch (Exception ex) {
            log.debug("内置漏扫探测失败 host={} port={}", host, port, ex);
            observations.add(
                observation(host, port, plugin.id(), false, "", "探测异常，已跳过"));
            continue;
          }
          if (!probe.reachable()) {
            observations.add(
                observation(host, port, plugin.id(), false, "", "端口未开放或未通过只读握手"));
            continue;
          }
          observations.add(
              observation(host, port, plugin.id(), false, truncate(probe.banner(), 300),
                  "只读探测到可达服务，不能单独判定为漏洞"));
          if (findings.size() < MAX_FINDINGS && vulnPlausible(plugin, probe)) {
            String severity = normalizeSeverity(plugin.severity());
            findings.add(
                new FindingDraft(
                    plugin.name(),
                    severity,
                    plugin.description() == null
                        ? "插件在授权主机上匹配到潜在问题，需人工确认。"
                        : plugin.description(),
                    "plugin="
                        + plugin.id()
                        + "; target="
                        + host
                        + ":"
                        + port
                        + "; banner="
                        + probe.banner(),
                    plugin.remediation() == null
                        ? "依据插件说明与厂商公告确认影响，修复后复测。"
                        : plugin.remediation(),
                    item.vulnerabilityCode()));
            matches.add(
                Map.of(
                    "pluginId", plugin.id(),
                    "name", plugin.name(),
                    "severity", severity,
                    "port", port,
                    "target", host));
          }
        }
      }
    } finally {
      pool.shutdownNow();
    }

    Map<String, Object> data = new LinkedHashMap<>();
    data.put("host", host);
    data.put("selectedPluginCount", selected.size());
    data.put("observationCount", observations.size());
    data.put("matchCount", matches.size());
    data.put("matches", matches);
    data.put("skipped", List.copyOf(skipped));
    return new ToolExecutionResult(
        "内置漏扫完成：探测 "
            + selected.size()
            + " 个插件，记录 "
            + observations.size()
            + " 条资产观察、"
            + matches.size()
            + " 项潜在匹配",
        data,
        findings);
  }

  private HostPlugin readPlugin(ScannerPocSelectionService.SelectedPoc item) {
    if (item.file() == null || !Files.isRegularFile(item.file())) {
      throw new ApiException("插件本地文件缺失，请重新同步漏洞库");
    }
    Path file = item.file();
    Path parent = file.getParent();
    return pluginParser.parse(parent, file, 2L * 1024 * 1024);
  }

  private Set<Integer> authorizedPluginPorts(HostPlugin plugin, Set<Integer> allowed) {
    LinkedHashSet<Integer> ports = new LinkedHashSet<>();
    List<String> protocols = plugin.protocols() == null ? List.of() : plugin.protocols();
    for (String protocol : protocols) {
      String value = protocol == null ? "" : protocol.trim().toLowerCase(Locale.ROOT);
      if (value.matches("\\d{1,5}")) {
        int port = Integer.parseInt(value);
        if (port >= PortRangeParser.MIN_PORT && port <= PortRangeParser.MAX_PORT) ports.add(port);
      } else {
        Integer port = WELL_KNOWN_PORTS.get(value);
        if (port != null) ports.add(port);
      }
    }
    LinkedHashSet<Integer> result = new LinkedHashSet<>();
    for (int port : ports) {
      if (allowed.contains(port)) result.add(port);
    }
    return result;
  }

  private boolean vulnPlausible(HostPlugin plugin, ProbeResult probe) {
    String safety = plugin.scanSafety();
    if (!"SAFE".equalsIgnoreCase(safety) && !"REVIEW_REQUIRED".equalsIgnoreCase(safety)) {
      return false;
    }
    return probe.banner() != null && !probe.banner().isBlank();
  }

  private String normalizeSeverity(String value) {
    String severity = value == null ? "INFO" : value.toUpperCase(Locale.ROOT);
    return SEVERITIES.contains(severity) ? severity : "INFO";
  }

  private Map<String, Object> observation(
      String host, int port, String pluginId, boolean isVuln, String banner, String note) {
    Map<String, Object> map = new LinkedHashMap<>();
    map.put("host", host);
    map.put("port", port);
    map.put("plugin", pluginId);
    map.put("assessmentType", "ASSET_OBSERVATION");
    map.put("vulnerability", isVuln);
    map.put("banner", banner);
    map.put("note", note);
    return map;
  }

  private static String truncate(String value, int max) {
    String clean = value == null ? "" : value;
    return clean.length() <= max ? clean : clean.substring(0, max) + "…";
  }

  /** 只读探测器：对 host:port 做受控 TCP 连接并读取回显。 */
  public interface BannerProber {
    ProbeResult probe(String host, int port) throws Exception;
  }

  record ProbeResult(boolean reachable, String banner) {}

  static final class SocketBannerProber implements BannerProber {
    @Override
    public ProbeResult probe(String host, int port) {
      try (Socket socket = new Socket()) {
        socket.connect(new InetSocketAddress(host, port), CONNECT_TIMEOUT_MS);
        socket.setSoTimeout(READ_TIMEOUT_MS);
        byte[] buffer = new byte[MAX_BANNER_BYTES];
        int read = 0;
        try (InputStream in = socket.getInputStream()) {
          read = in.read(buffer);
        } catch (Exception ignored) {
          // 有些服务在只读时不会主动推指纹，仍视为可达。
        }
        String banner = read > 0 ? new String(buffer, 0, Math.min(read, MAX_BANNER_BYTES), StandardCharsets.UTF_8) : "";
        return new ProbeResult(true, banner.trim());
      } catch (Exception ex) {
        return new ProbeResult(false, "");
      }
    }
  }
}