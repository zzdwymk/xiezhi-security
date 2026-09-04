package com.bachelor.toolbox.tool;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.common.ProcessEnvironmentSanitizer;
import com.bachelor.toolbox.dependency.ExecutableLocator;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.TargetPolicyService;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
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
 * 受控的 Metasploit 工具。
 *
 * <p>在已授权主机与端口边界内，通过 {@code msfconsole -q} 以非交互方式运行用户明确选择的
 * Metasploit auxiliary/scanner 或 exploit 模块，解析 MSF 输出标记（[*]/[+]）并将落在授权
 * 范围内的命中作为 {@link FindingDraft} 提交。未安装 MSF 时按现有安全工具同款流程报「工具不可用」。
 */
@Component
public class MsfScanTool implements SecurityTool {
  private static final int MAX_OUTPUT_BYTES = 2 * 1024 * 1024;
  private static final int MAX_FINDINGS = 500;

  /** MSF 输出中的服务/端口坐标，用于把命中约束在授权主机内。 */
  private static final Pattern COORDINATE =
      Pattern.compile("(\\d{1,3}(?:\\.\\d{1,3}){3})(?:[:\\s/]+)(\\d{1,5})");

  /** 服务端强制固定、禁止用户在参数中覆盖的秘买主机/端口/载荷纬度。 */
  private static final Set<String> FORBIDDEN_OPTION_KEYS =
      Set.of(
          "RHOST", "RHOSTS", "RPORT", "LHOST", "LPORT", "PAYLOAD", "CMD", "COMMAND", "SHELL",
          "CHOST", "CPORT");

  /** MSF 用 [+ ] 标注正向命中（登录成功、发现可利用点等）。 */
  private static final Pattern POSITIVE_LINE =
      Pattern.compile("^\\s*\\[(\\+)\\]\\s*(.*)$");

  private final TargetPolicyService policy;
  private final ExecutableLocator locator;
  private final String configuredExecutable;
  private final long timeoutSeconds;

  public MsfScanTool(
      TargetPolicyService policy,
      ExecutableLocator locator,
      @Value("${toolbox.execution.msf-path:msfconsole}") String configuredExecutable,
      @Value("${toolbox.execution.msf-timeout-seconds:600}") long timeoutSeconds) {
    this.policy = policy;
    this.locator = locator;
    this.configuredExecutable = configuredExecutable;
    this.timeoutSeconds = timeoutSeconds;
  }

  @Override
  public String code() {
    return "msf_scan";
  }

  @Override
  public String displayName() {
    return "Metasploit 模块";
  }

  @Override
  public String description() {
    return "在授权主机与端口上执行用户明确选择的 Metasploit auxiliary/scanner/exploit 模块";
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
    String module = requireModule(parameters);
    Map<String, String> options = sanitizedOptions(parameters);
    Path executable = requireExecutable();
    List<String> command = buildCommand(executable, host, module, options);
    observer.command(command);
    observer.heartbeat("Metasploit 模块已启动");
    ProcessBuilder builder = ProcessEnvironmentSanitizer.sanitize(new ProcessBuilder(command));
    builder.redirectErrorStream(true);
    Process process = builder.start();
    try {
      String output = waitFor(process, observer, module);
      if (process.exitValue() != 0) {
        throw new ApiException(
            "msfconsole 执行失败，退出码 " + process.exitValue() + "：" + abbreviate(output, 300));
      }
      observer.progressPercent(100d, "MSF 模块完成，正在解析结果");
      return parseOutput(host, module, output);
    } finally {
      if (process.isAlive()) process.destroyForcibly();
    }
  }

  private String requireModule(Map<String, Object> parameters) {
    String module =
        Objects.toString(parameters.getOrDefault("module", ""), "").trim().toLowerCase(Locale.ROOT);
    if (module.isBlank() || module.length() > 256) {
      throw new ApiException("请选择有效的 Metasploit 模块");
    }
    if (!(module.startsWith("auxiliary/") || module.startsWith("exploit/"))) {
      throw new ApiException("仅允许 auxiliary 或 exploit 模块在授权范围内执行");
    }
    if (module.matches(".*(\\s|[;&|>`$'\"]).*")
        || module.contains("..")
        || module.contains("\\")) {
      throw new ApiException("模块路径不合法");
    }
    return module;
  }

  private Map<String, String> sanitizedOptions(Map<String, Object> parameters) {
    Map<String, String> result = new LinkedHashMap<>();
    Object raw = parameters.get("options");
    if (!(raw instanceof Map<?, ?>)) {
      return result;
    }
    for (Map.Entry<?, ?> entry : ((Map<?, ?>) raw).entrySet()) {
      String key = String.valueOf(entry.getKey()).trim().toUpperCase(Locale.ROOT);
      if (FORBIDDEN_OPTION_KEYS.contains(key)) {
        throw new ApiException("不允许覆盖 MSF 选项：" + key);
      }
      String value = Objects.toString(entry.getValue(), "").trim();
      if (key.isBlank() || value.contains(";") || value.contains("\n")) {
        throw new ApiException("MSF 模块参数不合法");
      }
      result.put(key, value);
    }
    return result;
  }

  private Path requireExecutable() {
    Path executable =
        locator
            .find(candidates())
            .orElseThrow(
                () -> new ApiException("未找到 msfconsole，请先安装 MetasploitFramework"));
    if (!Files.isRegularFile(executable)) {
      throw new ApiException("未找到已配置的 msfconsole 可执行文件");
    }
    return executable.toAbsolutePath().normalize();
  }

  private List<String> candidates() {
    Set<String> candidates = new LinkedHashSet<>();
    if (configuredExecutable != null && !configuredExecutable.isBlank()) {
      candidates.add(configuredExecutable.trim());
    }
    candidates.add("msfconsole");
    candidates.add("msfconsole.bat");
    return List.copyOf(candidates);
  }

  List<String> buildCommand(Path executable, String host, String module, Map<String, String> options) {
    boolean isExploit = module.startsWith("exploit/");
    StringBuilder script = new StringBuilder();
    script.append("use ").append(module).append(';');
    // 强制固定授权主机边界，杜绝借 MSF 选项越权探测。
    script.append("setg RHOSTS ").append(host).append(';');
    if (isExploit) {
      // 默认仅做可达性与模块尝试，不自动反弹会话。
      script.append("setg PAYLOAD generic/shell_reverse_tcp;");
    }
    for (Map.Entry<String, String> entry : options.entrySet()) {
      script.append("set ").append(entry.getKey()).append(' ').append(entry.getValue()).append(';');
    }
    script.append(isExploit ? "check" : "run").append(" -j; sleep 2; jobs -k");
    return List.of(executable.toString(), "-q", "-x", script.toString());
  }

  ToolExecutionResult parseOutput(String expectedHost, String module, String outputText) {
    List<FindingDraft> findings = new ArrayList<>();
    List<Map<String, Object>> matches = new ArrayList<>();
    List<String> lines = outputText == null ? List.of() : List.of(outputText.split("\\R"));

    int total = 0;
    for (String line : lines) {
      Matcher positive = POSITIVE_LINE.matcher(line);
      if (!positive.matches()) {
        continue;
      }
      String message = positive.group(2).trim();
      if (message.isBlank()) {
        continue;
      }
      // 仅纳入落在授权主机内的命中。
      if (!inScope(expectedHost, message)) {
        continue;
      }
      total++;
      if (findings.size() >= MAX_FINDINGS) {
        continue;
      }
      String title = shortTitle(message, module);
      String severity = inferSeverity(message);
      findings.add(
          new FindingDraft(
              title,
              severity,
              "Metasploit " + module + " 在授权主机上得到正向命中，需人工确认影响与利用条件。",
              line,
              "依据 MSF 模块说明与厂商公告确认影响，修复后使用同一模块在相同主机端口复测。",
              "MSF-" + sha256Short(line)));
      matches.add(Map.of("module", module, "message", message, "severity", severity));
    }

    Map<String, Object> data = new LinkedHashMap<>();
    data.put("host", expectedHost);
    data.put("module", module);
    data.put("matchCount", total);
    data.put("matches", matches);
    data.put("truncated", total > MAX_FINDINGS);
    data.put("dependencyPresent", true);
    return new ToolExecutionResult(
        "Metasploit " + module + " 执行完成，得到 " + total + " 项正向命中",
        data,
        findings);
  }

  private boolean inScope(String expectedHost, String message) {
    Matcher matcher = COORDINATE.matcher(message);
    while (matcher.find()) {
      if (expectedHost.equalsIgnoreCase(matcher.group(1))) {
        return true;
      }
    }
    // 无坐标但包含授权主机名字符串也视为落界。
    return message.toLowerCase(Locale.ROOT).contains(expectedHost.toLowerCase(Locale.ROOT));
  }

  private String shortTitle(String message, String module) {
    String marker = module.contains("scanner/") || module.contains("auxiliary/") ? "MSF 辅助检测" : "MSF 利用命中";
    if (message.toLowerCase(Locale.ROOT).contains("success")
        || message.toLowerCase(Locale.ROOT).contains("login")
        || message.toLowerCase(Locale.ROOT).contains("vulnerable")) {
      return marker + "（疑似成功/可利用）";
    }
    return marker;
  }

  private String inferSeverity(String message) {
    String upper = message.toUpperCase(Locale.ROOT);
    if (upper.contains("RCE") || upper.contains("EXPLOIT") || upper.contains("SYSTEM")) {
      return "HIGH";
    }
    if (upper.contains("LOGIN") || upper.contains("AUTH") || upper.contains("UNAUTHORIZED")) {
      return "MEDIUM";
    }
    return "LOW";
  }

  private String sha256Short(String value) {
    try {
      byte[] digest =
          java.security.MessageDigest.getInstance("SHA-256")
              .digest(value.getBytes(StandardCharsets.UTF_8));
      return java.util.HexFormat.of().formatHex(digest).substring(0, 12).toUpperCase(Locale.ROOT);
    } catch (Exception ignore) {
      return Integer.toHexString(value.hashCode()).toUpperCase(Locale.ROOT);
    }
  }

  private String waitFor(Process process, ToolExecutionObserver observer, String module)
      throws Exception {
    ExecutorService reader = Executors.newSingleThreadExecutor();
    Future<String> output = reader.submit(() -> readLimited(process.getInputStream()));
    try {
      long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(timeoutSeconds);
      while (!process.waitFor(250, TimeUnit.MILLISECONDS)) {
        observer.heartbeat("Metasploit 正在运行：" + module);
        if (observer.isCancellationRequested()) {
          process.destroyForcibly();
          process.waitFor(5, TimeUnit.SECONDS);
          throw new ApiException("任务已取消");
        }
        if (System.nanoTime() >= deadline) {
          process.destroyForcibly();
          process.waitFor(5, TimeUnit.SECONDS);
          throw new ApiException("Metasploit 执行超过 " + timeoutSeconds + " 秒，已强制终止");
        }
      }
      return output.get(10, TimeUnit.SECONDS);
    } finally {
      reader.shutdownNow();
    }
  }

  private String readLimited(InputStream input) throws Exception {
    byte[] data = input.readNBytes(MAX_OUTPUT_BYTES + 1);
    if (data.length > MAX_OUTPUT_BYTES) {
      throw new ApiException("Metasploit 输出超过安全大小限制");
    }
    return new String(data, StandardCharsets.UTF_8);
  }

  private String abbreviate(String value, int max) {
    String clean = value == null ? "" : value.replaceAll("\\s+", " ").trim();
    return clean.length() <= max ? clean : clean.substring(0, max) + "…";
  }
}