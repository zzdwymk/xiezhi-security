package com.bachelor.toolbox.tool;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.common.ProcessEnvironmentSanitizer;
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
  private static final Pattern NATIVE_PERCENT =
      Pattern.compile("(?i)About\\s+([0-9]+(?:\\.[0-9]+)?)%\\s+done");

  private final TargetPolicyService policy;
  private final PortRangeParser portRangeParser;
  private final Path executable;
  private final int maxPorts;
  private final long timeoutSeconds;
  private final long fullTimeoutSeconds;
  private final NmapXmlParser parser = new NmapXmlParser();

  public NmapServiceScanTool(
      TargetPolicyService policy,
      PortRangeParser portRangeParser,
      @Value("${toolbox.execution.nmap-path:D:/software/Nmap/nmap.exe}") String executable,
      @Value("${toolbox.execution.max-nmap-ports-per-task:65535}") int maxPorts,
      @Value("${toolbox.execution.nmap-timeout-seconds:60}") long timeoutSeconds,
      @Value("${toolbox.execution.nmap-full-timeout-seconds:600}") long fullTimeoutSeconds) {
    this.policy = policy;
    this.portRangeParser = portRangeParser;
    this.executable = Path.of(executable).toAbsolutePath().normalize();
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
    if (!Set.of("quick", "service").contains(mode))
      throw new ApiException("Nmap mode 仅支持 quick 或 service");
    if (!Files.isRegularFile(executable)) throw new ApiException("未找到已配置的 Nmap 可执行文件");

    List<String> command = buildCommand(host, canonicalPorts, mode);
    observer.command(command);
    observer.heartbeat("Nmap 已启动，等待原生扫描进度");
    long effectiveTimeoutSeconds =
        "1-65535".equals(canonicalPorts) ? fullTimeoutSeconds : timeoutSeconds;
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
      data.put("requestedPorts", canonicalPorts);
      data.put("requestedPortCount", requested.size());
      data.put("openPorts", openPortObservations);
      data.put(
          "rawSummary",
          Map.of("exitCode", process.exitValue(), "openPortCount", parsed.openPorts().size()));
      return new ToolExecutionResult(
          "Nmap 已扫描 "
              + requested.size()
              + " 个授权端口，发现 "
              + openPortObservations.size()
              + " 个开放端口（已归类为资产暴露面，不自动判定为漏洞）",
          data,
          List.of());
    } finally {
      if (process.isAlive()) process.destroyForcibly();
      readers.shutdownNow();
    }
  }

  List<String> buildCommand(String host, String canonicalPorts, String mode) {
    List<String> command = new ArrayList<>();
    command.add(executable.toString());
    command.addAll(List.of("-sT", "-n", "-Pn", "--stats-every", "1s"));
    if ("service".equals(mode)) command.addAll(List.of("-sV", "--version-light"));
    if ("1-65535".equals(canonicalPorts)) command.add("-p-");
    else command.addAll(List.of("-p", canonicalPorts));
    command.addAll(List.of("-oX", "-", host));
    return List.copyOf(command);
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
