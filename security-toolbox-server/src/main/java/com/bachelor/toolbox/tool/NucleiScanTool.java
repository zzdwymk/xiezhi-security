package com.bachelor.toolbox.tool;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.common.ProcessEnvironmentSanitizer;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.PortRangeParser;
import com.bachelor.toolbox.target.TargetPolicyService;
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
          "traversal");

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
            : pocSelection.resolve(NucleiTemplateCatalogService.SOURCE_TYPE, parameters, true);
    boolean allPocs = pocSelection != null && pocSelection.selectsAll(parameters);
    String canonicalPorts = ports.canonicalizeCompact(target.getAllowedPorts(), maxPorts);
    assertExecutableIfAbsolute();
    if (selected.isEmpty() && !hasTemplates())
      throw new ApiException("未安装 Nuclei 模板，请先在依赖检测页面更新或重新安装 Nuclei");
    Path targetList = createTargetList(target, host, canonicalPorts);
    List<String> command =
        buildCommand(
            targetList,
            allPocs
                ? List.of(templatesPath)
                : selected.stream().map(ScannerPocSelectionService.SelectedPoc::file).toList());
    observer.command(command);
    ProcessBuilder builder = new ProcessBuilder(command).redirectErrorStream(true);
    Process process = ProcessEnvironmentSanitizer.sanitize(builder).start();
    ExecutorService readerExecutor = Executors.newSingleThreadExecutor();
    Future<String> output = readerExecutor.submit(() -> readLimited(process, observer));
    try {
      long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(timeoutSeconds);
      while (!process.waitFor(250, TimeUnit.MILLISECONDS)) {
        observer.heartbeat("Nuclei 正在按安全模板检查授权目标");
        if (observer.isCancellationRequested()) {
          process.destroyForcibly();
          process.waitFor(5, TimeUnit.SECONDS);
          throw new ApiException("任务已取消");
        }
        if (System.nanoTime() >= deadline) {
          process.destroyForcibly();
          process.waitFor(5, TimeUnit.SECONDS);
          throw new ApiException("Nuclei 扫描超过 " + timeoutSeconds + " 秒，已强制终止");
        }
      }
      String outputText = output.get(10, TimeUnit.SECONDS);
      if (process.exitValue() != 0) {
        throw new ApiException(
            "Nuclei 执行失败，退出码 " + process.exitValue() + "：" + abbreviate(outputText, 500));
      }
      observer.progressPercent(100d, "Nuclei 扫描完成，正在解析匹配结果");
      return parseOutput(host, canonicalPorts, outputText);
    } finally {
      if (process.isAlive()) process.destroyForcibly();
      readerExecutor.shutdownNow();
      Files.deleteIfExists(targetList);
    }
  }

  List<String> buildCommand(Path targetList) {
    return buildCommand(targetList, List.of());
  }

  List<String> buildCommand(Path targetList, List<Path> selectedTemplates) {
    List<String> command = new ArrayList<>();
    command.add(executable);
    command.addAll(List.of("-list", targetList.toString()));
    List<Path> templates = selectedTemplates.isEmpty() ? safeTemplateDirectories() : selectedTemplates;
    for (Path safeDirectory : templates) {
      command.add("-templates");
      command.add(safeDirectory.toString());
    }
    if (selectedTemplates.isEmpty()) command.addAll(List.of("-pt", "http,ssl", "-ni"));
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
    if (selectedTemplates.isEmpty()) command.addAll(List.of("-etags", EXCLUDED_TAGS));
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

  private Path createTargetList(AuthorizedTarget target, String host, String canonicalPorts)
      throws Exception {
    Path file = Files.createTempFile("secbox-nuclei-targets-", ".txt");
    List<String> targets = new ArrayList<>();
    String value = target.getTargetValue();
    if (value.startsWith("http://") || value.startsWith("https://")) {
      targets.add(policy.validatedHttpUri(target).toString());
    } else {
      String safeHost = host.contains(":") ? "[" + host + "]" : host;
      for (Integer port : ports.parse(canonicalPorts, maxPorts)) {
        targets.add("http://" + safeHost + ":" + port);
        targets.add("https://" + safeHost + ":" + port);
      }
    }
    Files.write(file, targets, StandardCharsets.UTF_8);
    return file;
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

  private String readLimited(Process process, ToolExecutionObserver observer) throws Exception {
    StringBuilder output = new StringBuilder();
    try (BufferedReader reader =
        new BufferedReader(
            new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
      String line;
      while ((line = reader.readLine()) != null) {
        if (output.length() + line.length() > MAX_OUTPUT_CHARS) {
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
