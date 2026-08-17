package com.bachelor.toolbox.tool;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.common.ProcessEnvironmentSanitizer;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.TargetPolicyService;
import com.bachelor.toolbox.vulnerability.ScannerPocCatalogService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class XrayScanTool implements SecurityTool {
  private static final int MAX_FINDINGS = 500;
  private static final int MAX_OUTPUT_CHARS = 2 * 1024 * 1024;
  private static final int MAX_JSON_BYTES = 16 * 1024 * 1024;

  private final TargetPolicyService policy;
  private final ObjectMapper objectMapper;
  private final ScannerPocSelectionService pocSelection;
  private final String executable;
  private final long timeoutSeconds;

  public XrayScanTool(
      TargetPolicyService policy,
      ObjectMapper objectMapper,
      ScannerPocSelectionService pocSelection,
      @Value("${toolbox.execution.xray-path:xray}") String executable,
      @Value("${toolbox.execution.xray-timeout-seconds:900}") long timeoutSeconds) {
    this.policy = policy;
    this.objectMapper = objectMapper;
    this.pocSelection = pocSelection;
    this.executable = executable;
    this.timeoutSeconds = timeoutSeconds;
  }

  @Override
  public String code() {
    return "xray_scan";
  }

  @Override
  public String displayName() {
    return "Xray PoC 扫描";
  }

  @Override
  public String description() {
    return "在授权 Web 目标上执行用户明确选择的 Xray PoC";
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
    URI targetUri = policy.validatedHttpUri(target);
    List<ScannerPocSelectionService.SelectedPoc> selected =
        pocSelection.resolve(ScannerPocCatalogService.XRAY, parameters, false);
    boolean allPocs = pocSelection.selectsAll(parameters);
    assertExecutableIfAbsolute();
    Path work = Files.createTempDirectory("xiezhi-xray-");
    Path output = work.resolve("result.json");
    try {
      initializeConfig(work);
      List<String> command = buildCommand(targetUri, selected, output, allPocs);
      observer.command(command);
      ProcessBuilder builder = new ProcessBuilder(command).directory(work.toFile()).redirectErrorStream(true);
      Process process = ProcessEnvironmentSanitizer.sanitize(builder).start();
      String stdout = waitFor(process, observer, "Xray 正在执行已选择的 PoC", timeoutSeconds);
      if (process.exitValue() != 0) {
        throw new ApiException("Xray 执行失败，退出码 " + process.exitValue() + "：" + abbreviate(stdout, 500));
      }
      observer.progressPercent(100d, "Xray 扫描完成，正在解析结果");
      return parseOutput(targetUri, selected, readJson(output));
    } finally {
      deleteTree(work);
    }
  }

  List<String> buildCommand(
      URI target, List<ScannerPocSelectionService.SelectedPoc> selected, Path jsonOutput) {
    return buildCommand(target, selected, jsonOutput, false);
  }

  List<String> buildCommand(
      URI target,
      List<ScannerPocSelectionService.SelectedPoc> selected,
      Path jsonOutput,
      boolean allPocs) {
    List<String> command = new ArrayList<>();
    command.add(executable);
    command.add("--log-level");
    command.add("warn");
    command.add("webscan");
    command.add("--plugins");
    command.add("phantasm");
    if (!allPocs) {
    String pocIds =
        selected.stream().map(ScannerPocSelectionService.SelectedPoc::externalId).reduce((left, right) -> left + "," + right).orElseThrow();
      command.add("--poc");
      command.add(pocIds);
    }
    command.add("--url");
    command.add(target.toString());
    command.add("--json-output");
    command.add(jsonOutput.toString());
    return List.copyOf(command);
  }

  ToolExecutionResult parseOutput(
      URI expectedTarget,
      List<ScannerPocSelectionService.SelectedPoc> selected,
      String json) {
    List<FindingDraft> findings = new ArrayList<>();
    List<Map<String, Object>> matches = new ArrayList<>();
    try {
      JsonNode root = json == null || json.isBlank() ? objectMapper.createArrayNode() : objectMapper.readTree(json);
      List<JsonNode> items = resultItems(root);
      for (JsonNode item : items) {
        ScannerPocSelectionService.SelectedPoc poc = resolvePoc(item, selected);
        String matched = matchedTarget(item);
        assertAuthorized(expectedTarget, matched);
        JsonNode detail = item.path("detail");
        String title = firstText(detail.path("vuln_class"), item.path("vuln_class"), item.path("name"));
        if (title.isBlank()) title = poc.name();
        String severity = normalizeSeverity(firstText(detail.path("level"), item.path("level"), item.path("severity")));
        if (findings.size() < MAX_FINDINGS) {
          findings.add(
              new FindingDraft(
                  title,
                  severity,
                  "Xray PoC 在授权目标上匹配到潜在安全问题，需结合组件版本和业务环境人工确认。",
                  "poc=" + poc.externalId() + "; target=" + matched,
                  "依据 Xray PoC 引用与厂商公告确认影响，修复后使用同一 PoC 复测。",
                  poc.vulnerabilityCode()));
        }
        matches.add(
            Map.of(
                "pocId", poc.externalId(),
                "name", title,
                "severity", severity,
                "target", matched));
      }
    } catch (ApiException ex) {
      throw ex;
    } catch (Exception ex) {
      throw new ApiException("无法解析 Xray JSON 扫描结果");
    }
    Map<String, Object> data = new LinkedHashMap<>();
    data.put("selectedPocCount", selected.size());
    data.put("matchCount", matches.size());
    data.put("matches", matches);
    return new ToolExecutionResult("Xray 扫描完成，匹配 " + matches.size() + " 项潜在问题", data, findings);
  }

  private void initializeConfig(Path work) throws Exception {
    List<String> command = List.of(executable, "version");
    ProcessBuilder builder = new ProcessBuilder(command).directory(work.toFile()).redirectErrorStream(true);
    Process process = ProcessEnvironmentSanitizer.sanitize(builder).start();
    waitFor(process, ToolExecutionObserver.NOOP, "正在初始化 Xray 隔离配置", 15);
    if (process.exitValue() != 0) throw new ApiException("Xray 隔离配置初始化失败");
  }

  private List<JsonNode> resultItems(JsonNode root) {
    List<JsonNode> result = new ArrayList<>();
    if (root == null || root.isNull()) return result;
    if (root.isArray()) {
      root.forEach(item -> result.addAll(resultItems(item)));
      return result;
    }
    if (!root.isObject()) return result;
    if (root.has("plugin") && (root.has("target") || root.has("detail"))) {
      result.add(root);
      return result;
    }
    for (String field : List.of("results", "vulnerabilities", "items")) {
      if (root.path(field).isArray()) result.addAll(resultItems(root.path(field)));
    }
    return result;
  }

  private ScannerPocSelectionService.SelectedPoc resolvePoc(
      JsonNode item, List<ScannerPocSelectionService.SelectedPoc> selected) {
    String direct =
        firstText(
            item.path("poc"),
            item.path("poc_name"),
            item.path("vuln_class"),
            item.path("detail").path("poc"),
            item.path("detail").path("vuln_class"));
    for (ScannerPocSelectionService.SelectedPoc poc : selected) {
      if (poc.externalId().equals(direct)) return poc;
    }
    String serialized = item.toString();
    List<ScannerPocSelectionService.SelectedPoc> embedded =
        selected.stream().filter(poc -> serialized.contains(poc.externalId())).toList();
    if (embedded.size() == 1) return embedded.get(0);
    if (selected.size() == 1) return selected.get(0);
    throw new ApiException("Xray 返回结果无法映射到唯一的已选 PoC");
  }

  private String matchedTarget(JsonNode item) {
    JsonNode target = item.path("target");
    String value = target.isTextual() ? target.asText("") : firstText(target.path("url"), target.path("addr"));
    if (value.isBlank()) {
      JsonNode detail = item.path("detail");
      value = firstText(detail.path("addr"), detail.path("url"), detail.path("target"));
    }
    if (value.isBlank()) throw new ApiException("Xray 结果缺少可核验的匹配目标");
    return value;
  }

  private String waitFor(
      Process process, ToolExecutionObserver observer, String operation, long timeout) throws Exception {
    ExecutorService reader = Executors.newSingleThreadExecutor();
    Future<String> output = reader.submit(() -> readLimited(process));
    try {
      long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(timeout);
      while (!process.waitFor(250, TimeUnit.MILLISECONDS)) {
        observer.heartbeat(operation);
        if (observer.isCancellationRequested()) {
          process.destroyForcibly();
          throw new ApiException("任务已取消");
        }
        if (System.nanoTime() >= deadline) {
          process.destroyForcibly();
          throw new ApiException("Xray 扫描超过 " + timeout + " 秒，已强制终止");
        }
      }
      return output.get(10, TimeUnit.SECONDS);
    } finally {
      if (process.isAlive()) process.destroyForcibly();
      reader.shutdownNow();
    }
  }

  private String readLimited(Process process) throws Exception {
    StringBuilder output = new StringBuilder();
    try (BufferedReader reader =
        new BufferedReader(new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
      String line;
      while ((line = reader.readLine()) != null) {
        if (output.length() + line.length() > MAX_OUTPUT_CHARS) {
          process.destroyForcibly();
          throw new ApiException("Xray 输出超过安全大小限制");
        }
        output.append(line).append('\n');
      }
    }
    return output.toString();
  }

  private String readJson(Path file) throws Exception {
    if (!Files.exists(file)) return "[]";
    long size = Files.size(file);
    if (size > MAX_JSON_BYTES) throw new ApiException("Xray JSON 结果超过安全大小限制");
    return Files.readString(file, StandardCharsets.UTF_8);
  }

  private void assertAuthorized(URI expected, String actual) {
    try {
      URI value = URI.create(actual.contains("://") ? actual : expected.getScheme() + "://" + actual);
      int expectedPort = port(expected);
      int actualPort = port(value);
      if (value.getHost() == null
          || !value.getHost().equalsIgnoreCase(expected.getHost())
          || actualPort != expectedPort) {
        throw new ApiException("Xray 返回了授权范围外的匹配目标：" + actual);
      }
    } catch (IllegalArgumentException ex) {
      throw new ApiException("Xray 返回的匹配目标格式无效");
    }
  }

  private int port(URI uri) {
    return uri.getPort() > 0 ? uri.getPort() : "https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80;
  }

  private String firstText(JsonNode... values) {
    for (JsonNode value : values) {
      String text = value == null ? "" : value.asText("").trim();
      if (!text.isBlank()) return text;
    }
    return "";
  }

  private String normalizeSeverity(String value) {
    String severity = value == null ? "" : value.toUpperCase(Locale.ROOT);
    return Set.of("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO").contains(severity)
        ? severity
        : "INFO";
  }

  private void assertExecutableIfAbsolute() {
    Path path = Path.of(executable);
    if (path.isAbsolute() && !Files.isRegularFile(path)) {
      throw new ApiException("未找到 Xray 可执行文件：" + path);
    }
  }

  private void deleteTree(Path root) {
    if (root == null || !Files.exists(root)) return;
    try (var paths = Files.walk(root)) {
      paths.sorted(Comparator.reverseOrder())
          .forEach(
              path -> {
                try {
                  Files.deleteIfExists(path);
                } catch (Exception ignored) {
                }
              });
    } catch (Exception ignored) {
    }
  }

  private String abbreviate(String value, int max) {
    String clean = value == null ? "" : value.replaceAll("\\s+", " ").trim();
    return clean.length() <= max ? clean : clean.substring(0, max) + "…";
  }
}
