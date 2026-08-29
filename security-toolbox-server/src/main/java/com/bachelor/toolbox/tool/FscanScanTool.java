package com.bachelor.toolbox.tool;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.common.ProcessEnvironmentSanitizer;
import com.bachelor.toolbox.dependency.ExecutableLocator;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.PortRangeParser;
import com.bachelor.toolbox.target.TargetPolicyService;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * 受控的主机内网扫描工具（fscan）。
 *
 * <p>仅在已授权目标与端口范围内运行进程内 fscan 子进程，产出的端口/服务作为资产暴露面，
 * 匹配到的弱口令、漏洞指纹等作为 {@link FindingDraft} 提交。默认关闭爆破、模糊与破坏性检测，
 * 由用户显式选择更高风险的扫描强度。
 */
@Component
public class FscanScanTool implements SecurityTool {
  private static final int MAX_OUTPUT_BYTES = 2 * 1024 * 1024;
  private static final int MAX_FINDINGS = 500;
  private static final int MAX_DATA_PORTS = 20_000;
  private static final int MAX_READ_BYTES = 2 * 1024 * 1024;

  /** 形如 IP:端口 的单端口坐标，用于从输出行中抓取授权主机开放端口。 */
  private static final Pattern PORT_LINE = Pattern.compile("(\\d{1,3}(?:\\.\\d{1,3}){3}):(\\d{1,5})");

  /** 表明该行属于风险提示（很可能已成漏洞）的标记关键词。 */
  private static final List<String> FLAG_KEYWORDS =
      List.of(
          "UNAUTHORIZED", "未授权", "WEAK", "弱口令", "BRUTE", "爆破", "RCE",
          "SQLINJECTION", "SQL注入", "EXPLOIT", "VULN", "INFO");
  private static final Pattern FLAG_MARKER = Pattern.compile("(?i)\\[\\s*(?:vuln|weak|login|netinfo|info)[^]]*\\]");

  private final TargetPolicyService policy;
  private final PortRangeParser portRangeParser;
  private final ExecutableLocator locator;
  private final String configuredExecutable;
  private final int maxPorts;
  private final long timeoutSeconds;

  public FscanScanTool(
      TargetPolicyService policy,
      PortRangeParser portRangeParser,
      ExecutableLocator locator,
      @Value("${toolbox.execution.fscan-path:fscan}") String configuredExecutable,
      @Value("${toolbox.execution.max-fscan-ports-per-task:65535}") int maxPorts,
      @Value("${toolbox.execution.fscan-timeout-seconds:600}") long timeoutSeconds) {
    this.policy = policy;
    this.portRangeParser = portRangeParser;
    this.locator = locator;
    this.configuredExecutable = configuredExecutable;
    this.maxPorts = maxPorts;
    this.timeoutSeconds = timeoutSeconds;
  }

  @Override
  public String code() {
    return "fscan_scan";
  }

  @Override
  public String displayName() {
    return "fscan 主机快速扫描";
  }

  @Override
  public String description() {
    return "在授权主机与端口范围内使用 fscan 执行端口、服务指纹与安全漏洞指纹检测";
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
    String requestedText =
        Objects.toString(parameters.getOrDefault("ports", target.getAllowedPorts()), "");
    String canonicalPorts = portRangeParser.canonicalizeCompact(requestedText, maxPorts);
    if (!allowed.containsAll(portRangeParser.parse(canonicalPorts, maxPorts))) {
      throw new ApiException("fscan 请求端口超出目标授权端口范围");
    }
    String mode = resolveVulnMode(parameters);
    Path executable = requireExecutable();
    Path outputFile = Files.createTempFile("xiezhi-fscan-", ".txt");
    try {
      List<String> command = buildCommand(executable, host, canonicalPorts, mode, outputFile);
      observer.command(command);
      observer.heartbeat("fscan 已启动，等待原生识别输出");
      ProcessBuilder builder = ProcessEnvironmentSanitizer.sanitize(new ProcessBuilder(command));
      builder.redirectErrorStream(true);
      Process process = builder.start();
      try {
        String stdout = waitForProcess(process, observer, timeoutSeconds);
        StringBuilder combined = new StringBuilder(abbreviate(stdout, 2000));
        try {
          String fileText = readFileLimited(outputFile);
          if (!fileText.isBlank()) {
            combined.append(System.lineSeparator()).append(fileText);
          }
        } catch (Exception ignored) {
          // 极端情况下 fscan 可能不写目标文件，保留控制台输出即可。
        }
        if (process.exitValue() != 0) {
          throw new ApiException(
              "fscan 执行失败，退出码 "
                  + process.exitValue()
                  + "："
                  + abbreviate(combined.toString(), 300));
        }
        observer.progressPercent(100d, "fscan 完成，正在解析识别结果");
        return parseOutput(host, canonicalPorts, combined.toString());
      } finally {
        if (process.isAlive()) process.destroyForcibly();
      }
    } finally {
      Files.deleteIfExists(outputFile);
    }
  }

  private String resolveVulnMode(Map<String, Object> parameters) {
    String upperMode =
        Objects.toString(parameters.getOrDefault("vulnMode", "safe"), "").trim()
            .toUpperCase(Locale.ROOT);
    if (!Set.of("SAFE", "FINGERPRINT", "FULL").contains(upperMode)) {
      throw new ApiException("fscan vulnMode 仅支持 safe、fingerprint 或 full");
    }
    return upperMode;
  }

  List<String> buildCommand(Path executable, String host, String canonicalPorts, String vulnMode) {
    return buildCommand(executable, host, canonicalPorts, vulnMode, null);
  }

  List<String> buildCommand(
      Path executable, String host, String canonicalPorts, String vulnMode, Path outputFile) {
    List<String> command = new ArrayList<>();
    command.add(executable.toString());
    command.add("-h");
    command.add(host);
    command.add("-p");
    command.add(canonicalPorts);
    // 跳过 Ping 探测，避免授权目标未响应 ICMP 时漏扫；不做额外域名识别。
    command.add("-np");
    if ("SAFE".equals(vulnMode) || "FINGERPRINT".equals(vulnMode)) {
      // 高应激检测默认关闭：不执行 POC 漏洞验证。
      command.add("-nopoc");
    }
    if ("SAFE".equals(vulnMode)) {
      // 完全安全的模式：同时关闭爆破与模糊测试。
      command.add("-nobr");
      command.add("-nofuzz");
    }
    if (outputFile != null) {
      command.add("-o");
      command.add(outputFile.toString());
    }
    return List.copyOf(command);
  }

  private Path requireExecutable() {
    Path executable =
        locator
            .find(candidates())
            .orElseThrow(() -> new ApiException("未找到已配置的 fscan 可执行文件"));
    if (!Files.isRegularFile(executable)) {
      throw new ApiException("未找到已配置的 fscan 可执行文件");
    }
    return executable.toAbsolutePath().normalize();
  }

  private List<String> candidates() {
    Set<String> candidates = new LinkedHashSet<>();
    if (configuredExecutable != null && !configuredExecutable.isBlank()) {
      candidates.add(configuredExecutable.trim());
    }
    candidates.add("fscan");
    candidates.add("fscan.exe");
    return List.copyOf(candidates);
  }

  private String waitForProcess(Process process, ToolExecutionObserver observer, long timeout)
      throws Exception {
    ExecutorService reader = Executors.newSingleThreadExecutor();
    Future<String> output = reader.submit(() -> readLimited(process.getInputStream()));
    try {
      long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(timeout);
      while (!process.waitFor(250, TimeUnit.MILLISECONDS)) {
        observer.heartbeat("fscan 正在运行");
        if (observer.isCancellationRequested()) {
          process.destroyForcibly();
          process.waitFor(5, TimeUnit.SECONDS);
          throw new ApiException("任务已取消");
        }
        if (System.nanoTime() >= deadline) {
          process.destroyForcibly();
          process.waitFor(5, TimeUnit.SECONDS);
          throw new ApiException("fscan 扫描超过 " + timeout + " 秒，已强制终止");
        }
      }
      return output.get(10, TimeUnit.SECONDS);
    } finally {
      reader.shutdownNow();
    }
  }

  private String readLimited(InputStream input) throws Exception {
    byte[] data = input.readNBytes(MAX_READ_BYTES + 1);
    if (data.length > MAX_READ_BYTES) {
      throw new ApiException("fscan 输出超过安全大小限制");
    }
    return new String(data, StandardCharsets.UTF_8);
  }

  private String readFileLimited(Path file) throws Exception {
    if (!Files.exists(file)) return "";
    long size = Files.size(file);
    if (size > MAX_OUTPUT_BYTES) throw new ApiException("fscan 结果文件超过安全大小限制");
    return Files.readString(file, StandardCharsets.UTF_8);
  }

  ToolExecutionResult parseOutput(String host, String canonicalPorts, String outputText) {
    List<FindingDraft> findings = new ArrayList<>();
    List<Map<String, Object>> openPorts = new ArrayList<>();
    List<Map<String, Object>> matches = new ArrayList<>();
    List<String> lines = outputText == null ? List.of() : List.of(outputText.split("\\R"));

    // 第一遍：抽取授权主机上的开放端口。
    Set<String> uniquePorts = new LinkedHashSet<>();
    for (String line : lines) {
      collectOpenPorts(host, line, uniquePorts);
    }

    // 第二遍：识别风险标记并生成 FindingDraft。
    int total = 0;
    for (String line : lines) {
      Map<String, Object> finding = interpretFindingLine(host, line);
      if (finding == null) {
        continue;
      }
      total++;
      if (findings.size() >= MAX_FINDINGS) {
        continue;
      }
      String title = Objects.toString(finding.get("title"), "fscan 风险提示");
      String severity = normalizeSeverity((String) finding.get("severity"));
      String evidence = Objects.toString(finding.get("evidence"), line);
      findings.add(
          new FindingDraft(
              title,
              severity,
              "fscan 在授权主机上匹配到潜在问题，需结合服务版本与业务环境人工确认。",
              evidence,
              "依据 fscan 结果与厂商公告确认影响，修复后使用相同主机与端口复测。",
              fscanVulnCode(evidence)));
      matches.add(Map.of("title", title, "severity", severity, "detail", evidence));
    }

    for (String port : uniquePorts) {
      Map<String, Object> observation = new LinkedHashMap<>();
      observation.put("host", host);
      observation.put("port", port);
      observation.put("assessmentType", "ASSET_OBSERVATION");
      observation.put("vulnerability", false);
      observation.put("note", "开放端口仅代表可达服务，不能单独判定为漏洞");
      openPorts.add(observation);
    }

    Map<String, Object> data = new LinkedHashMap<>();
    data.put("host", host);
    data.put("requestedPorts", canonicalPorts);
    data.put("openPortCount", openPorts.size());
    data.put("openPorts", openPorts);
    data.put("matchCount", total);
    data.put("matches", matches);
    data.put("truncated", total > MAX_FINDINGS);
    return new ToolExecutionResult(
        "fscan 已扫描授权主机，发现 "
            + openPorts.size()
            + " 个开放端口、"
            + total
            + " 项潜在风险记录",
        data,
        findings);
  }

  private void collectOpenPorts(String expectedHost, String line, Set<String> output) {
    if (line == null) return;
    Matcher matcher = PORT_LINE.matcher(line);
    while (matcher.find() && output.size() < MAX_DATA_PORTS) {
      String hostToken = matcher.group(1);
      String port = matcher.group(2);
      if (hostToken.equalsIgnoreCase(expectedHost)) {
        output.add(port);
      }
    }
  }

  private Map<String, Object> interpretFindingLine(String expectedHost, String line) {
    if (line == null || line.isBlank()) {
      return null;
    }
    String upper = line.toUpperCase(Locale.ROOT);
    boolean flagged =
        FLAG_MARKER.matcher(upper).find() || FLAG_KEYWORDS.stream().anyMatch(upper::contains);
    if (!flagged) {
      return null;
    }
    // 仅当该行确认落在授权主机边界内才纳入，避免越权匹配漏网。
    String scopedHost = extractScopeHost(line);
    if (scopedHost == null) {
      return null;
    }
    if (!expectedHost.equalsIgnoreCase(scopedHost)
        && !line.toLowerCase(Locale.ROOT).contains(expectedHost.toLowerCase(Locale.ROOT))) {
      return null;
    }

    String clean = line.replaceAll("\\s+", " ").trim();
    Map<String, Object> result = new LinkedHashMap<>();
    result.put("title", shortTitle(clean));
    result.put("severity", inferSeverity(clean));
    result.put("evidence", clean);
    return result;
  }

  private String normalizeSeverity(String value) {
    String severity = value == null ? "INFO" : value.toUpperCase(Locale.ROOT);
    return Set.of("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO").contains(severity)
        ? severity
        : "INFO";
  }

  /** 从行中尽量取到目标 IP，用于授权归属校验。 */
  private String extractScopeHost(String line) {
    Matcher matcher = PORT_LINE.matcher(line);
    return matcher.find() ? matcher.group(1).toLowerCase(Locale.ROOT) : null;
  }

  private String shortTitle(String line) {
    String lower = line.toLowerCase(Locale.ROOT);
    if (lower.contains("unauthorized") || lower.contains("未授权")) return "疑似未授权访问";
    if (lower.contains("weak") || lower.contains("弱口令") || lower.contains("brute")) {
      return "疑似弱口令 / 爆破风险";
    }
    if (lower.contains("rce")) return "疑似远程代码执行风险";
    if (lower.contains("sqlinjection") || lower.contains("sql")) return "疑似 SQL 注入风险";
    return "fscan 风险提示";
  }

  private String inferSeverity(String line) {
    String upper = line.toUpperCase(Locale.ROOT);
    if (upper.contains("CRITICAL") || upper.contains("RCE")) return "HIGH";
    if (upper.contains("弱口令") || upper.contains("HIGH")) return "HIGH";
    if (upper.contains("MEDIUM") || upper.contains("未授权") || upper.contains("UNAUTHORIZED")) {
      return "MEDIUM";
    }
    return "LOW";
  }

  private String fscanVulnCode(String line) {
    String normalized = line.replaceAll("\\s+", "").toLowerCase(Locale.ROOT);
    return "FSCAN-" + sha256Short(normalized);
  }

  private String sha256Short(String value) {
    try {
      byte[] digest =
          MessageDigest.getInstance("SHA-256")
              .digest(value.getBytes(StandardCharsets.UTF_8));
      return HexFormat.of().formatHex(digest).substring(0, 12).toUpperCase(Locale.ROOT);
    } catch (Exception ignore) {
      return Integer.toHexString(value.hashCode()).toUpperCase(Locale.ROOT);
    }
  }

  private String abbreviate(String value, int max) {
    String clean = value == null ? "" : value.replaceAll("\\s+", " ").trim();
    return clean.length() <= max ? clean : clean.substring(0, max) + "…";
  }
}