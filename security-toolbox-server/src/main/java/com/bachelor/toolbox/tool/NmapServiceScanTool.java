package com.bachelor.toolbox.tool;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.common.ProcessEnvironmentSanitizer;
import com.bachelor.toolbox.dependency.NmapExecutableResolver;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.PortRangeParser;
import com.bachelor.toolbox.target.TargetPolicyService;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
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

@Component
public class NmapServiceScanTool implements SecurityTool {
  private static final int MAX_OUTPUT_BYTES = 2 * 1024 * 1024;
  /** 与 Zenmap 官方默认扫描配置文件对齐的受控模式；取值与前端下拉、AI 运行时枚举保持一致。 */
  static final List<String> NMAP_MODES =
      List.of(
          "quick",
          "regular",
          "intense",
          "intense_udp",
          "intense_all_tcp",
          "intense_no_ping",
          "ping",
          "quick_plus",
          "quick_trace",
          "slow_comprehensive",
          // 兼容历史：service 等价于 -sV 轻量服务识别。
          "service");
  private static final Pattern NATIVE_PERCENT =
      Pattern.compile("(?i)About\\s+([0-9]+(?:\\.[0-9]+)?)%\\s+done");

  private final TargetPolicyService policy;
  private final PortRangeParser portRangeParser;
  private final NmapExecutableResolver executableResolver;
  private final int maxPorts;
  private final long timeoutSeconds;
  private final long fullTimeoutSeconds;
  private final NmapXmlParser parser = new NmapXmlParser();

  public NmapServiceScanTool(
      TargetPolicyService policy,
      PortRangeParser portRangeParser,
      NmapExecutableResolver executableResolver,
      @Value("${toolbox.execution.max-nmap-ports-per-task:65535}") int maxPorts,
      @Value("${toolbox.execution.nmap-timeout-seconds:60}") long timeoutSeconds,
      @Value("${toolbox.execution.nmap-full-timeout-seconds:600}") long fullTimeoutSeconds) {
    this.policy = policy;
    this.portRangeParser = portRangeParser;
    this.executableResolver = executableResolver;
    this.maxPorts = maxPorts;
    this.timeoutSeconds = timeoutSeconds;
    this.fullTimeoutSeconds = fullTimeoutSeconds;
  }

  @Override
  public String code() {
    return "nmap_service_scan";
  }

  @Override
  public String displayName() {
    return "Nmap 服务识别";
  }

  @Override
  public String description() {
    return "仅对已授权目标和端口执行受控 TCP 连接与轻量服务识别";
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
    Set<Integer> requested = portRangeParser.parse(canonicalPorts, maxPorts);
    if (!allowed.containsAll(requested)) throw new ApiException("Nmap 请求端口超出目标授权端口范围");
    String mode = Objects.toString(parameters.getOrDefault("mode", "quick"), "");
    if (!NMAP_MODES.contains(mode))
      throw new ApiException("Nmap 扫描模式无效，仅支持 " + String.join("、", NMAP_MODES));
    Path executable = requireExecutable();

    List<String> command = buildCommand(executable, host, canonicalPorts, mode);
    observer.command(command);
    observer.heartbeat("Nmap 已启动，等待原生扫描进度");
    long effectiveTimeoutSeconds = timeoutFor(mode, canonicalPorts);
    ProcessBuilder builder = ProcessEnvironmentSanitizer.sanitize(new ProcessBuilder(command));
    Process process = builder.start();
    ExecutorService readers = Executors.newFixedThreadPool(2);
    Future<String> stdout = readers.submit(() -> readLimited(process.getInputStream()));
    Future<String> stderr =
        readers.submit(() -> readDiagnostics(process.getErrorStream(), observer));
    try {
      long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(effectiveTimeoutSeconds);
      while (!process.waitFor(250, TimeUnit.MILLISECONDS)) {
        observer.heartbeat("Nmap 正在扫描 " + requested.size() + " 个授权端口");
        if (observer.isCancellationRequested()) {
          process.destroyForcibly();
          process.waitFor(5, TimeUnit.SECONDS);
          throw new ApiException("任务已取消");
        }
        if (System.nanoTime() >= deadline) {
          process.destroyForcibly();
          process.waitFor(5, TimeUnit.SECONDS);
          throw new ApiException("Nmap 扫描超过 " + effectiveTimeoutSeconds + " 秒，已强制终止");
        }
      }
      String xml = stdout.get(5, TimeUnit.SECONDS);
      String diagnostics = stderr.get(5, TimeUnit.SECONDS);
      if (process.exitValue() != 0) {
        String suffix = diagnostics.isBlank() ? "" : "：" + abbreviate(diagnostics, 300);
        throw new ApiException("Nmap 执行失败，退出码 " + process.exitValue() + suffix);
      }
      observer.progressPercent(100d, "Nmap 扫描完成，正在解析 XML 输出");
      return parseResult(xml, host, mode, canonicalPorts, requested.size(), process.exitValue());
    } finally {
      if (process.isAlive()) process.destroyForcibly();
      readers.shutdownNow();
    }
  }

  ToolExecutionResult parseResult(
      String xml, String host, String mode, String requestedPorts, int requestedPortCount, int exitCode) {
    var parsed = parser.parse(xml);
    List<Map<String, Object>> openPortObservations =
        parsed.openPorts().stream()
            .map(
                port -> {
                  Map<String, Object> observation = new LinkedHashMap<>(port);
                  observation.put("assessmentType", "ASSET_OBSERVATION");
                  observation.put("vulnerability", false);
                  observation.put("note", "开放端口仅代表可达服务，不能单独判定为漏洞");
                  return observation;
                })
            .toList();
    Map<String, Object> data = new LinkedHashMap<>();
    data.put("host", host);
    data.put("mode", mode);
    data.put("requestedPorts", requestedPorts);
    data.put("requestedPortCount", requestedPortCount);
    data.put(
        "evidenceNote",
        "portStates 仅记录 XML 明确列出的逐端口状态；extraports 是状态计数汇总，只有明确的 ports 字段才能对应具体端口。"
            + "未出现的端口不能推断为 closed；仅有 openPorts 的历史结果也不能区分其他端口是 closed、filtered 或未记录。"
            + "hostStatuses 的主机状态和 reason 原样来自 Nmap，不能单独证明端口可达。");
    data.put("hostStatuses", parsed.hostStatuses());
    data.put("openPorts", openPortObservations);
    data.put("extraports", parsed.extraports());
    data.put("portStates", parsed.portStates());
    data.put(
        "rawSummary",
        Map.of("exitCode", exitCode, "openPortCount", parsed.openPorts().size()));
    return new ToolExecutionResult(
        "Nmap 已完成 "
            + requestedPortCount
            + " 个授权端口的扫描请求，记录 "
            + openPortObservations.size()
            + " 个开放端口（已归类为资产暴露面，不自动判定为漏洞）",
        data,
        List.of());
  }

  List<String> buildCommand(String host, String canonicalPorts, String mode) {
    return buildCommand(requireExecutable(), host, canonicalPorts, mode);
  }

  private List<String> buildCommand(
      Path executable, String host, String canonicalPorts, String mode) {
    List<String> command = new ArrayList<>();
    command.add(executable.toString());
    // -sT 是本平台唯一的 TCP 扫描类型来源，任何模式下都只出现一次：Nmap
    // 明确拒绝同时指定多种 TCP 扫描类型（"more than one type of TCP scan"）。
    // UDP 必须与 TCP 合并为 -sSU 一个参数，分开写成 -sU -sT 同样会被拒绝。
    boolean hostDiscovery = "ping".equals(mode) || "quick_trace".equals(mode);
    boolean udp = "intense_udp".equals(mode) || "slow_comprehensive".equals(mode);
    command.add(udp ? "-sSU" : "-sT");
    command.add("-n");
    switch (mode) {
      case "quick" -> {
        // 纯 TCP 连接扫描：Nmap 内部按批并行，全段 65535 约 15-30 秒，
        // 比逐个串行建连快约两个数量级。-Pn 跳过禁 ping 主机的发现等待，
        // 否则目标不回 ICMP 时光是发现阶段就要耗掉数十秒。
        command.addAll(List.of("-Pn", "-T4"));
      }
      case "regular" -> command.add("-v");
      case "intense" -> command.addAll(List.of("-T4", "-A", "-v"));
      case "intense_udp" -> command.addAll(List.of("-T4", "-A", "-v"));
      case "intense_all_tcp" -> command.addAll(List.of("-T4", "-A", "-v"));
      case "intense_no_ping" -> command.addAll(List.of("-T4", "-A", "-v", "-Pn"));
      case "ping" -> command.addAll(List.of("-sn", "-PE", "-PS443", "-PA80"));
      case "quick_plus", "service" -> command.addAll(List.of("-sV", "-T4", "-O", "--version-light"));
      case "quick_trace" -> command.addAll(List.of("-sn", "--traceroute"));
      case "slow_comprehensive" -> command.addAll(
          List.of("-T4", "-A", "-v", "-PE", "-PS80", "-PA443", "-PP", "--script", "default"));
      default -> throw new ApiException("Nmap 扫描模式无效：" + mode);
    }
    // 端口选择：全端口统一用 -p-；主机发现类模式不扫描端口。
    if ("intense_all_tcp".equals(mode) || "slow_comprehensive".equals(mode)) {
      command.add("-p-");
    } else if (!hostDiscovery) {
      if ("1-65535".equals(canonicalPorts)) command.add("-p-");
      else command.addAll(List.of("-p", canonicalPorts));
    }
    command.addAll(List.of("--stats-every", "1s"));
    command.addAll(List.of("-oX", "-", host));
    return List.copyOf(command);
  }

  /**
   * Time budget for one run.
   *
   * <p>A full-range sweep needs the long budget, but port count is not the only cost driver:
   * UDP probes wait for a timeout before concluding "closed|filtered", and NSE scripts add
   * several more probes per open port. Giving those modes the short default made them fail on
   * a healthy target with "任务执行超时", which looks like a product defect to the operator.
   * Slow modes therefore get the long budget regardless of how few ports were requested.
   */
  long timeoutFor(String mode, String canonicalPorts) {
    boolean fullRange = "1-65535".equals(canonicalPorts);
    boolean slowMode = "slow_comprehensive".equals(mode) || "intense_udp".equals(mode);
    return fullRange || slowMode ? fullTimeoutSeconds : timeoutSeconds;
  }

  private Path requireExecutable() {
    Path executable =
        executableResolver
            .find()
            .orElseThrow(() -> new ApiException("未找到已配置的 Nmap 可执行文件"));
    if (!Files.isRegularFile(executable)) {
      throw new ApiException("未找到已配置的 Nmap 可执行文件");
    }
    return executable.toAbsolutePath().normalize();
  }

  private String readLimited(InputStream input) throws Exception {
    byte[] data = input.readNBytes(MAX_OUTPUT_BYTES + 1);
    if (data.length > MAX_OUTPUT_BYTES) throw new ApiException("Nmap 输出超过安全大小限制");
    return new String(data, StandardCharsets.UTF_8);
  }

  private String readDiagnostics(InputStream input, ToolExecutionObserver observer)
      throws Exception {
    StringBuilder output = new StringBuilder();
    try (BufferedReader reader =
        new BufferedReader(new InputStreamReader(input, StandardCharsets.UTF_8))) {
      String line;
      while ((line = reader.readLine()) != null) {
        if (output.length() + line.length() > MAX_OUTPUT_BYTES) {
          throw new ApiException("Nmap 诊断输出超过安全大小限制");
        }
        output.append(line).append('\n');
        Matcher matcher = NATIVE_PERCENT.matcher(line);
        if (matcher.find()) {
          observer.progressPercent(
              Double.parseDouble(matcher.group(1)), "Nmap " + matcher.group(1) + "%");
        } else {
          observer.heartbeat("Nmap 正在运行");
        }
      }
    }
    return output.toString();
  }

  private String abbreviate(String value, int maxLength) {
    String normalized = value.replaceAll("\\s+", " ").trim();
    return normalized.length() <= maxLength ? normalized : normalized.substring(0, maxLength) + "…";
  }
}
