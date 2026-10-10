package com.bachelor.toolbox.tool;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.common.ProcessEnvironmentSanitizer;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.PortRangeParser;
import com.bachelor.toolbox.target.TargetPolicyService;
import com.bachelor.toolbox.target.WebTargetResolver;
import com.bachelor.toolbox.vulnerability.NucleiTemplateCatalogService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class NucleiScanTool implements SecurityTool {
  private static final int MAX_FINDINGS = 500;
  private static final int MAX_OUTPUT_CHARS = 16 * 1024 * 1024;
  private static final Set<String> ALLOWED_SEVERITIES =
      Set.of("info", "low", "medium", "high", "critical");
  private static final String EXCLUDED_TAGS =
      String.join(
          ",",
          "dos",
          "local",
          "fuzz",
          "fuzzing",
          "bruteforce",
          "brute-force",
          "txt-service",
          "intrusive",
          "instrusive",
          "default-login",
          "token-spray",
          "authenticated",
          "creds-stuffing",
          "phishing",
          "oast",
          "rce",
          "sqli",
          "xss",
          "ssrf",
          "lfi",
          "xxe",
          "ssti",
          "injection",
          "file-upload",
          "fileupload",
          "deserialization",
          "traversal",
          // OSINT/headless/DAST 模板多为 self-contained（访问其硬编码的外部地址，忽略扫描目标），
          // 既与“对授权主机做漏洞扫描”无关，又会让输出出现授权范围外的 matched-at 触发范围守卫而整单失败。
          "osint",
          "headless",
          "dast");

  private final TargetPolicyService policy;
  private final PortRangeParser ports;
  private final ObjectMapper objectMapper;
  private final ScannerPocSelectionService pocSelection;
  private final String executable;
  private final Path templatesPath;
  private final int maxPorts;
  private final long timeoutSeconds;

  @Autowired
  public NucleiScanTool(
      TargetPolicyService policy,
      PortRangeParser ports,
      ObjectMapper objectMapper,
      ScannerPocSelectionService pocSelection,
      @Value("${toolbox.execution.nuclei-path:nuclei}") String executable,
      @Value("${toolbox.execution.nuclei-templates-path:${user.home}/nuclei-templates}")
          String templatesPath,
      @Value("${toolbox.execution.max-nuclei-ports-per-task:65535}") int maxPorts,
      @Value("${toolbox.execution.nuclei-timeout-seconds:900}") long timeoutSeconds) {
    this.policy = policy;
    this.ports = ports;
    this.objectMapper = objectMapper;
    this.pocSelection = pocSelection;
    this.executable = executable;
    this.templatesPath = Path.of(templatesPath).toAbsolutePath().normalize();
    this.maxPorts = maxPorts;
    this.timeoutSeconds = timeoutSeconds;
  }

  NucleiScanTool(
      TargetPolicyService policy,
      PortRangeParser ports,
      ObjectMapper objectMapper,
      String executable,
      String templatesPath,
      int maxPorts,
      long timeoutSeconds) {
    this.policy = policy;
    this.ports = ports;
    this.objectMapper = objectMapper;
    this.pocSelection = null;
    this.executable = executable;
    this.templatesPath = Path.of(templatesPath).toAbsolutePath().normalize();
    this.maxPorts = maxPorts;
    this.timeoutSeconds = timeoutSeconds;
  }

  @Override
  public String code() {
    return "nuclei_scan";
  }

  @Override
  public String displayName() {
    return "Nuclei 通用漏洞扫描";
  }

  @Override
  public String description() {
    return "在授权目标与端口范围内运行受控 Nuclei 模板扫描";
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
    List<ScannerPocSelectionService.SelectedPoc> selected =
        pocSelection == null
            ? List.of()
            : pocSelection.resolve(
                NucleiTemplateCatalogService.SOURCE_TYPE,
                WebTargetResolver.scanParameters(parameters),
                true);
    boolean allPocs = pocSelection != null && pocSelection.selectsAll(parameters);
    String canonicalPorts = ports.canonicalizeCompact(target.getAllowedPorts(), maxPorts);
    assertExecutableIfAbsolute();
    if (selected.isEmpty() && !hasTemplates())
      throw new ApiException("未安装 Nuclei 模板，请先在依赖检测页面更新或重新安装 Nuclei");
    Path targetList = createTargetList(target, host, canonicalPorts, parameters);
    List<String> command =
        buildCommand(
            targetList,
            allPocs
                ? List.of(templatesPath)
                : selected.stream().map(ScannerPocSelectionService.SelectedPoc::file).toList(),
            allPocs);
    observer.command(command);
    ProcessBuilder builder = new ProcessBuilder(command).redirectErrorStream(true);
    Process process = ProcessEnvironmentSanitizer.sanitize(builder).start();
    try {
      return executeProcess(process, host, canonicalPorts, observer);
    } finally {
      if (process.isAlive()) process.destroyForcibly();
      Files.deleteIfExists(targetList);
    }
  }

  ToolExecutionResult executeProcess(
      Process process, String host, String canonicalPorts, ToolExecutionObserver observer)
      throws Exception {
    String outputText;
    try {
      outputText = waitFor(process, observer);
    } catch (NucleiOutputTimeoutException timeout) {
      // Use the same parser and host/port guard as a completed scan. A scope violation
      // rejects the entire output; it must not be relabeled as a harmless timeout.
      ToolExecutionResult observed = parseOutput(host, canonicalPorts, timeout.output);
      Map<String, Object> data = new LinkedHashMap<>(observed.data());
      data.put("partial", true);
      data.put("scanCompleted", false);
      data.put("terminationReason", "TIMEOUT");
      String summary = "Nuclei 扫描超时，未完整完成；已保留 " + observed.findings().size()
          + " 项已观察匹配，未完成部分不能判断为无风险";
      ToolExecutionTimeoutException failure = new ToolExecutionTimeoutException(
          summary, new ToolExecutionResult(summary, data, observed.findings()));
      failure.initCause(timeout);
      throw failure;
    }
    if (process.exitValue() != 0) {
      throw new ApiException(
          "Nuclei 执行失败，退出码 " + process.exitValue() + "：" + abbreviate(outputText, 500));
    }
    validateCompletedOutput(outputText);
    ToolExecutionResult result = parseOutput(host, canonicalPorts, outputText);
    observer.progressPercent(100d, "Nuclei 扫描完成，正在解析匹配结果");
    return result;
  }

  String waitFor(Process process, ToolExecutionObserver observer) throws Exception {
    StringBuffer capturedOutput = new StringBuffer();
    ExecutorService readerExecutor = Executors.newSingleThreadExecutor();
    Future<String> output = readerExecutor.submit(() -> readLimited(process, observer, capturedOutput));
    try {
      long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(timeoutSeconds);
      while (!process.waitFor(250, TimeUnit.MILLISECONDS)) {
        if (output.isDone()) output.get();
        observer.heartbeat("Nuclei 正在按安全模板检查授权目标");
        if (observer.isCancellationRequested()) {
          process.destroyForcibly();
          process.waitFor(5, TimeUnit.SECONDS);
          throw new ApiException("任务已取消");
        }
        if (System.nanoTime() >= deadline) {
          process.destroyForcibly();
          process.waitFor(5, TimeUnit.SECONDS);
          try {
            // Drain output already written before termination, within a bounded wait.
            output.get(1, TimeUnit.SECONDS);
          } catch (java.util.concurrent.ExecutionException failure) {
            // Closing a killed process's pipe may fail after valid complete lines.
            // Output-limit, observer and authorization failures still fail closed.
            if (!(failure.getCause() instanceof java.io.IOException)) throw failure;
          } catch (java.util.concurrent.TimeoutException ignored) {
            // The synchronized snapshot contains only lines the reader has obtained.
          }
          throw new NucleiOutputTimeoutException(
              "Nuclei 扫描超过 " + timeoutSeconds + " 秒，已强制终止", capturedOutput.toString());
        }
      }
      return output.get(10, TimeUnit.SECONDS);
    } finally {
      if (process.isAlive()) process.destroyForcibly();
      readerExecutor.shutdownNow();
    }
  }

  private static final class NucleiOutputTimeoutException extends java.util.concurrent.TimeoutException {
    private final String output;

    private NucleiOutputTimeoutException(String message, String output) {
      super(message);
      this.output = output;
    }
  }

  List<String> buildCommand(Path targetList) {
    return buildCommand(targetList, List.of(), false);
  }

  List<String> buildCommand(Path targetList, List<Path> selectedTemplates) {
    return buildCommand(targetList, selectedTemplates, false);
  }

  List<String> buildCommand(Path targetList, List<Path> selectedTemplates, boolean allPocs) {
    List<String> command = new ArrayList<>();
    command.add(executable);
    command.addAll(List.of("-list", targetList.toString()));
    List<Path> templates = selectedTemplates.isEmpty() ? safeTemplateDirectories() : selectedTemplates;
    for (Path safeDirectory : templates) {
      command.add("-templates");
      command.add(safeDirectory.toString());
    }
    // 全量/默认安全集都属于“非用户逐条选定”的受控扫描：限制为 http,ssl 协议（不启用 headless/code，
    // 避免 self-contained OSINT/headless 模板越界访问外部地址），并统一排除高危/自包含标签。
    // 仅当用户明确逐条选定模板时，才尊重其选择并放开 headless/code、不做标签排除。
    boolean controlledScan = selectedTemplates.isEmpty() || allPocs;
    if (controlledScan) command.addAll(List.of("-pt", "http,ssl", "-ni"));
    else command.addAll(List.of("-headless", "-code"));
    command.addAll(
        List.of(
            "-dr",
            "-dut",
            "-duc",
            "-or",
            "-ot",
            "-silent",
            "-jsonl",
            "-nc",
            "-stats",
            "-stats-json",
            "-si",
            "1",
            "-timeout",
            "10",
            "-retries",
            "1",
            "-rl",
            "50",
            "-c",
            "10",
            "-bs",
            "25"));
    if (controlledScan) command.addAll(List.of("-etags", EXCLUDED_TAGS));
    command.addAll(List.of("-severity", "info,low,medium,high,critical"));
    return List.copyOf(command);
  }

  ToolExecutionResult parseOutput(String host, String canonicalPorts, String jsonLines) {
    List<FindingDraft> findings = new ArrayList<>();
    List<Map<String, Object>> matches = new ArrayList<>();
    int total = 0;
    for (String line : jsonLines.split("\\R")) {
      if (line.isBlank() || !line.stripLeading().startsWith("{")) continue;
      try {
        JsonNode item = objectMapper.readTree(line);
        if (!item.hasNonNull("template-id")) continue;
        String templateId = item.path("template-id").asText("unknown-template");
        JsonNode info = item.path("info");
        String name = info.path("name").asText(templateId);
        String severity = info.path("severity").asText("info").toUpperCase(Locale.ROOT);
        String matchedAt = item.path("matched-at").asText(item.path("host").asText(host));
        if (!authorizedMatch(host, canonicalPorts, matchedAt)) {
          throw new ApiException("Nuclei 返回了授权范围外的匹配目标：" + matchedAt);
        }
        String matcher = item.path("matcher-name").asText("");
        String description =
            info.path("description").asText("Nuclei 官方模板在授权目标上匹配到潜在安全问题，需结合组件版本与业务环境人工确认。");
        String remediation =
            info.path("remediation").asText("核对模板引用的厂商公告与受影响组件版本，确认影响后升级、修补或限制暴露范围。");
        String cveIds = jsonValues(info.path("classification").path("cve-id"));
        String cweIds = jsonValues(info.path("classification").path("cwe-id"));
        String tags = jsonValues(info.path("tags"));
        total++;
        if (findings.size() >= MAX_FINDINGS) continue;
        String evidence =
            "template="
                + templateId
                + "; matched-at="
                + matchedAt
                + (matcher.isBlank() ? "" : "; matcher=" + matcher);
        findings.add(
            new FindingDraft(
                name,
                normalizeSeverity(severity),
                description,
                evidence,
                remediation,
                NucleiTemplateCatalogService.stableCodeFor(templateId)));
        Map<String, Object> match = new LinkedHashMap<>();
        match.put("templateId", templateId);
        match.put("name", name);
        match.put("severity", normalizeSeverity(severity));
        match.put("matchedAt", matchedAt);
        match.put("cveIds", cveIds);
        match.put("cweIds", cweIds);
        match.put("tags", tags);
        matches.add(match);
      } catch (ApiException ex) {
        throw ex;
      } catch (Exception ignored) {
        // Nuclei may emit a small amount of non-JSON diagnostic output; ignore it safely.
      }
    }
    Map<String, Object> data = new LinkedHashMap<>();
    data.put("host", host);
    data.put("requestedPorts", canonicalPorts);
    data.put("matchCount", total);
    data.put("matches", matches);
    data.put("truncated", total > MAX_FINDINGS);
    return new ToolExecutionResult("Nuclei 扫描完成，匹配 " + total + " 项潜在问题", data, findings);
  }

  private void validateCompletedOutput(String output) {
    JsonNode finalStats = null;
    for (String line : output.split("\\R")) {
      if (!line.stripLeading().startsWith("{")) continue;
      JsonNode item;
      try {
        item = objectMapper.readTree(line);
      } catch (Exception ex) {
        throw new ApiException("Nuclei 返回的检测结果不完整，无法判断是否存在漏洞，请重试");
      }
      if (item.has("template-id")) {
        if (item.path("template-id").asText("").isBlank()
            || item.path("matched-at").asText(item.path("host").asText("")).isBlank()) {
          throw new ApiException("Nuclei 返回的检测结果不完整，无法判断是否存在漏洞，请重试");
        }
      } else if (item.has("requests") || item.has("templates")) {
        finalStats = item;
      }
    }
    if (finalStats == null) {
      throw new ApiException("Nuclei 未提供有效的执行记录，无法确认检测是否完成，请检查扫描器后重试");
    }
    long templates = executionCount(finalStats, "templates");
    long hosts = executionCount(finalStats, "hosts");
    long requests = executionCount(finalStats, "requests");
    long errors = executionCount(finalStats, "errors");
    if (templates == 0 || hosts == 0 || requests == 0) {
      throw new ApiException("Nuclei 没有实际执行有效检测，请确认目标已启动、地址可访问且已选择可用规则后重试");
    }
    // Nuclei also increments requests for failed/skipped requests; exit code 0 and
    // 100% progress therefore do not demonstrate that the target responded.
    if (errors > 0) {
      throw new ApiException("Nuclei 检测过程中有请求失败，本次检测未完整完成，不能据此判断目标没有漏洞。请确认目标已开机、网站已启动且网络可达后重试");
    }
  }

  private long executionCount(JsonNode stats, String field) {
    String value = stats.path(field).asText("");
    if (!value.matches("0|[1-9][0-9]{0,17}")) {
      throw new ApiException("Nuclei 执行记录不完整，无法确认检测是否完成，请重试");
    }
    return Long.parseLong(value);
  }

  private Path createTargetList(AuthorizedTarget target, String host, String canonicalPorts,
      Map<String, Object> parameters)
      throws Exception {
    List<String> targets = targetEntries(target, host, canonicalPorts, parameters);
    Path file = Files.createTempFile("secbox-nuclei-targets-", ".txt");
    Files.write(file, targets, StandardCharsets.UTF_8);
    return file;
  }

  List<String> targetEntries(AuthorizedTarget target, String host, String canonicalPorts,
      Map<String, Object> parameters) {
    List<String> targets = new ArrayList<>();
    List<URI> resolvedBases = WebTargetResolver.basesFromParameters(parameters);
    Object rawBases = parameters == null ? null : parameters.get(WebTargetResolver.PARAM_RESOLVED_BASES);
    if (rawBases != null && (!(rawBases instanceof List<?> values) || values.size() != resolvedBases.size())) {
      throw new ApiException("Nuclei 目标地址格式异常，请重新选择授权目标");
    }
    if (!resolvedBases.isEmpty()) {
      for (URI base : resolvedBases) {
        if (!("http".equalsIgnoreCase(base.getScheme()) || "https".equalsIgnoreCase(base.getScheme()))
            || base.getRawUserInfo() != null || base.getRawFragment() != null
            || (base.getPort() != -1 && (base.getPort() < 1 || base.getPort() > 65535))
            || !authorizedMatch(host, canonicalPorts, base.toString())) {
          throw new ApiException("Nuclei 检测地址不在授权主机和端口范围内，请重新选择目标");
        }
        targets.add(base.toString());
      }
      return targets.stream().distinct().toList();
    }
    String value = target.getTargetValue();
    if (value.startsWith("http://") || value.startsWith("https://")) {
      targets.add(policy.validatedHttpUri(target).toString());
    } else {
      String safeHost = host.contains(":") ? "[" + host + "]" : host;
      for (Integer port : ports.parse(canonicalPorts, maxPorts)) {
        // Let Nuclei choose the working HTTP scheme for this authorized port.
        // Sending both explicit schemes makes normal HTTP-only services fail TLS.
        targets.add(safeHost + ":" + port);
      }
    }
    return targets;
  }

  private void assertExecutableIfAbsolute() {
    Path path = Path.of(executable);
    if (path.isAbsolute() && !Files.isRegularFile(path))
      throw new ApiException("未找到 Nuclei 可执行文件：" + path);
  }

  private boolean hasTemplates() {
    if (!Files.isDirectory(templatesPath)) return false;
    for (Path directory : safeTemplateDirectories()) {
      if (!Files.isDirectory(directory)) continue;
      try (var files = Files.walk(directory)) {
        if (files.anyMatch(
            path ->
                Files.isRegularFile(path)
                    && (path.toString().endsWith(".yaml") || path.toString().endsWith(".yml"))))
          return true;
      } catch (Exception ignored) {
        // Try the next conservative directory.
      }
    }
    return false;
  }

  private List<Path> safeTemplateDirectories() {
    return List.of(
        templatesPath.resolve("http/exposures").normalize(),
        templatesPath.resolve("http/misconfiguration").normalize(),
        templatesPath.resolve("http/technologies").normalize(),
        templatesPath.resolve("ssl").normalize());
  }

  private boolean authorizedMatch(String expectedHost, String canonicalPorts, String matchedAt) {
    try {
      String value = matchedAt.contains("://") ? matchedAt : "http://" + matchedAt;
      URI uri = URI.create(value);
      if (uri.getHost() == null || !uri.getHost().equalsIgnoreCase(expectedHost)) return false;
      int port =
          uri.getPort() > 0
              ? uri.getPort()
              : ("https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80);
      return ports.parse(canonicalPorts, maxPorts).contains(port);
    } catch (Exception ignored) {
      return false;
    }
  }

  private String readLimited(
      Process process, ToolExecutionObserver observer, StringBuffer output) throws Exception {
    try (BufferedReader reader =
        new BufferedReader(
            new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
      String line;
      while ((line = reader.readLine()) != null) {
        if (output.length() + line.length() + 1 > MAX_OUTPUT_CHARS) {
          process.destroyForcibly();
          throw new ApiException("Nuclei 输出超过安全大小限制");
        }
        output.append(line).append('\n');
        reportNativeProgress(line, observer);
      }
    }
    return output.toString();
  }

  private void reportNativeProgress(String line, ToolExecutionObserver observer) {
    if (line == null || !line.stripLeading().startsWith("{")) {
      observer.heartbeat("Nuclei 正在运行");
      return;
    }
    try {
      JsonNode stats = objectMapper.readTree(line);
      if (stats.hasNonNull("template-id")) {
        observer.heartbeat("Nuclei 已返回新的模板匹配结果");
        return;
      }
      JsonNode percentNode = stats.has("percent") ? stats.path("percent") : stats.path("progress");
      if (!percentNode.isMissingNode() && !percentNode.isNull()) {
        String raw = percentNode.asText("").replace("%", "").trim();
        if (!raw.isBlank()) {
          double percent = Double.parseDouble(raw);
          observer.progressPercent(percent, "Nuclei 原生进度 " + Math.round(percent) + "%");
          return;
        }
      }
      String requests = stats.path("requests").asText("");
      String matched = stats.path("matched").asText("");
      String detail =
          requests.isBlank()
              ? "Nuclei 正在运行"
              : "Nuclei 已发送 "
                  + requests
                  + " 个请求"
                  + (matched.isBlank() ? "" : "，匹配 " + matched + " 项");
      observer.heartbeat(detail);
    } catch (Exception ignored) {
      observer.heartbeat("Nuclei 正在运行");
    }
  }

  private String normalizeSeverity(String value) {
    return switch (value) {
      case "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO" -> value;
      default -> "INFO";
    };
  }

  private String jsonValues(JsonNode value) {
    if (value == null || value.isMissingNode() || value.isNull()) return "";
    if (value.isArray()) {
      List<String> values = new ArrayList<>();
      value.forEach(
          item -> {
            String text = item.asText("").trim();
            if (!text.isBlank()) values.add(text);
          });
      return String.join(",", values);
    }
    return value.asText("").trim();
  }

  private String abbreviate(String value, int max) {
    String clean = value.replaceAll("\\s+", " ").trim();
    return clean.length() <= max ? clean : clean.substring(0, max) + "…";
  }
}
