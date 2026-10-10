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
import java.util.concurrent.CancellationException;
import java.util.concurrent.TimeoutException;
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
  private static final Pattern SCAN_COMPLETION = Pattern.compile(
      "(?m)^\\[\\*]\\s*扫描任务完成，耗时[^\\r\\n]+，已扫描\\s+(\\d+)\\s+个目标\\s*$");

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
        StringBuilder combined = new StringBuilder(stdout);
        String fileText = readFileLimited(outputFile);
        if (!fileText.isBlank()) {
          combined.append(System.lineSeparator()).append(fileText);
        }
        if (process.exitValue() != 0) {
          throw new ApiException(
              "fscan 执行失败，退出码 "
                  + process.exitValue()
                  + "："
                  + abbreviate(combined.toString(), 300));
        }
        validateExecutionOutput(stdout);
        ToolExecutionResult result = parseOutput(host, canonicalPorts, combined.toString(), fileText);
        if (Integer.valueOf(0).equals(result.data().get("openPortCount")) && result.findings().isEmpty()) {
          throw new ApiException("未发现可访问的目标服务，无法判断是否存在漏洞。请确认目标已开机、服务已启动，并检查授权端口和网络连接。");
        }
        observer.progressPercent(100d, "fscan 已完成检测，正在整理结果");
        return result;
      } finally {
        if (process.isAlive()) process.destroyForcibly();
      }
    } finally {
      Files.deleteIfExists(outputFile);
    }
  }

  void validateExecutionOutput(String stdout) {
    if (stdout != null && stdout.lines().anyMatch(this::isConnectionFailure)) {
      throw new ApiException("部分目标服务连接失败，本次检测不完整。请检查目标服务、授权端口和网络连接后重试。");
    }
    Matcher completion = SCAN_COMPLETION.matcher(stdout == null ? "" : stdout);
    Long scanned = null;
    while (completion.find()) {
      try { scanned = Long.parseLong(completion.group(1)); }
      catch (NumberFormatException ex) { throw new ApiException("fscan 返回了无效的检测统计，本次检测未完成"); }
    }
    if (scanned == null) {
      throw new ApiException("fscan 未返回完整的检测统计，无法确认检测已完成。请检查扫描引擎后重试。");
    }
    if (scanned == 0) {
      throw new ApiException("未发现可访问的目标服务，无法判断是否存在漏洞。请确认目标已开机、服务已启动，并检查授权端口和网络连接。");
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
      // 完全安全的模式：关闭爆破。当前 fscan 版本不提供 -nofuzz；模糊/探测风险已由 -nopoc 关闭。
      command.add("-nobr");
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
          throw new CancellationException("任务已取消");
        }
        if (System.nanoTime() >= deadline) {
          process.destroyForcibly();
          process.waitFor(5, TimeUnit.SECONDS);
          throw new TimeoutException("fscan 扫描超过 " + timeout + " 秒，已强制终止");
        }
      }
      if (Thread.currentThread().isInterrupted() || observer.isCancellationRequested()) {
        throw new CancellationException("任务已取消");
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
    return parseOutput(host, canonicalPorts, outputText, "");
  }

  ToolExecutionResult parseOutput(String host, String canonicalPorts, String outputText, String resultFile) {
    List<FindingDraft> findings = new ArrayList<>();
    List<Map<String, Object>> openPorts = new ArrayList<>();
    List<Map<String, Object>> matches = new ArrayList<>();
    List<String> lines = outputText == null ? List.of() : List.of(outputText.split("\\R"));
    Set<Integer> scopedPorts = portRangeParser.parse(canonicalPorts, maxPorts);

    // 第一遍：抽取授权主机上的开放端口。
    Set<String> uniquePorts = new LinkedHashSet<>();
    // fscan 2.2 writes bare host:port rows to this file section. Its console URL
    // omits default ports, so requiring a console [+]/[*] prefix loses port 80.
    // Only parse the dedicated result file, not arbitrary console/banner text.
    boolean openPortSection = false;
    for (String rawLine : resultFile == null ? List.<String>of() : resultFile.lines().toList()) {
      String line = rawLine.strip();
      if (line.startsWith("#")) {
        openPortSection = line.equals("# ===== 开放端口 =====");
        continue;
      }
      if (!openPortSection) continue;
      Matcher address = PORT_LINE.matcher(line);
      if (uniquePorts.size() < MAX_DATA_PORTS && address.matches() && address.group(1).equalsIgnoreCase(host)
          && scopedPorts.contains(Integer.parseInt(address.group(2)))) {
        uniquePorts.add(Integer.toString(Integer.parseInt(address.group(2))));
      }
    }
    for (String line : lines) {
      if (isScopedObservation(host, scopedPorts, line)) collectOpenPorts(host, scopedPorts, line, uniquePorts);
    }

    // 第二遍：识别风险标记并生成 FindingDraft。
    int total = 0;
    for (String line : lines) {
      if (!isScopedObservation(host, scopedPorts, line)) continue;
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

    // 专项：SMBv1 / 老旧 Windows 暴露面。fscan 的 SMBInfo 指纹行（如
    // "[+] SMBInfo <ip>:445 [Windows 7/Server 2008 R2 (Build 7601)] <host> SMBv1"）
    // 被通用解析器归为 LOW，这里将其明确升格为一条中危“资产暴露面”结果（是否可被具体利用需另行确认）。
    String smbEvidence = null;
    for (String line : lines) {
      if (!isScopedObservation(host, scopedPorts, line)) continue;
      boolean smbV1 = line.contains("SMBv1") || line.toUpperCase(Locale.ROOT).contains("SMBGHOST");
      if (smbV1) {
        // fscan 输出常被合并为一整块，这里截取 SMBInfo/SMBv1 附近的片段作为“明确”的证据，
        // 避免把整幅 banner 作为证据。
        int idx = line.indexOf("SMBInfo");
        if (idx < 0) idx = line.indexOf("SMBv1");
        int from = idx < 0 ? 0 : Math.max(0, idx - 12);
        int to = idx < 0 ? line.length() : Math.min(line.length(), idx + 140);
        smbEvidence = line.substring(from, to).replaceAll("\\s+", " ").trim();
        break;
      }
    }
    if (smbEvidence != null && findings.size() < MAX_FINDINGS) {
      String smbTitle = "SMBv1 协议启用 / 老旧 Windows 暴露面";
      findings.add(
          new FindingDraft(
              smbTitle,
              "MEDIUM",
              "fscan SMB 指纹显示授权主机启用了 SMBv1（NT LM 0.12）且系统版本老旧。SMBv1 是 MS17-010"
                  + "（EternalBlue）、WannaCry 等高危漏洞的攻击面，且常伴随 SMB 消息签名关闭，属应尽快收敛的"
                  + "资产暴露面（是否可被具体利用需结合补丁状态另行确认）。",
              smbEvidence,
              "在目标上禁用 SMBv1（PowerShell：Set-SmbServerConfiguration -EnableSMB1Protocol $false，"
                  + "或移除 SMB1Protocol 功能），升级到受支持的 Windows 版本，启用 SMB 签名，并对 135/139/445"
                  + " 端口实施网络访问控制后复测。",
              "STB-SMB-SMBV1"));
      matches.add(Map.of("title", smbTitle, "severity", "MEDIUM", "detail", smbEvidence));
      total++;
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

  private boolean isScopedObservation(String host, Set<Integer> scopedPorts, String line) {
    if (line == null || !line.stripLeading().matches("^\\[(?:\\+|\\*)].*")) return false;
    if (isConnectionFailure(line)) return false;
    Matcher address = PORT_LINE.matcher(line);
    return address.find() && address.group(1).equalsIgnoreCase(host)
        && scopedPorts.contains(Integer.parseInt(address.group(2)));
  }

  private boolean isConnectionFailure(String line) {
    String lower = line.toLowerCase(Locale.ROOT);
    // Native HTTP metadata contains target-controlled text, not scanner errors.
    int metadataStart = lower.length();
    for (String field : List.of("title:", "banner:", "[product:", "server:")) {
      int index = lower.indexOf(field);
      if (index >= 0) metadataStart = Math.min(metadataStart, index);
    }
    lower = lower.substring(0, metadataStart);
    return lower.contains("connection refused") || lower.contains("connectex")
        || lower.contains("i/o timeout") || lower.contains("no route to host")
        || lower.contains("network is unreachable") || lower.contains("dial tcp")
        || lower.contains("连接失败") || lower.contains("连接超时");
  }

  private void collectOpenPorts(String expectedHost, Set<Integer> scopedPorts, String line, Set<String> output) {
    if (line == null) return;
    Matcher matcher = PORT_LINE.matcher(line);
    if (matcher.find() && output.size() < MAX_DATA_PORTS) {
      String hostToken = matcher.group(1);
      String port = matcher.group(2);
      if (hostToken.equalsIgnoreCase(expectedHost) && scopedPorts.contains(Integer.parseInt(port))) {
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
    if (!expectedHost.equalsIgnoreCase(scopedHost)) {
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
