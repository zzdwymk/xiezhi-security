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
import java.nio.file.StandardCopyOption;
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
public class AfrogScanTool implements SecurityTool {
  private static final int MAX_FINDINGS = 500;
  private static final int MAX_OUTPUT_CHARS = 2 * 1024 * 1024;
  private static final int MAX_JSON_BYTES = 16 * 1024 * 1024;

  private final TargetPolicyService policy;
  private final ObjectMapper objectMapper;
  private final ScannerPocSelectionService pocSelection;
  private final String executable;
  private final long timeoutSeconds;

  public AfrogScanTool(
      TargetPolicyService policy,
      ObjectMapper objectMapper,
      ScannerPocSelectionService pocSelection,
      @Value("${toolbox.execution.afrog-path:afrog}") String executable,
      @Value("${toolbox.execution.afrog-timeout-seconds:900}") long timeoutSeconds) {
    this.policy = policy;
    this.objectMapper = objectMapper;
    this.pocSelection = pocSelection;
    this.executable = executable;
    this.timeoutSeconds = timeoutSeconds;
  }

  @Override
  public String code() {
    return "afrog_scan";
  }

  @Override
  public String displayName() {
    return "Afrog PoC 扫描";
  }

  @Override
  public String description() {
    return "在授权 Web 目标上执行用户明确选择的 Afrog PoC";
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
        pocSelection.resolve(ScannerPocCatalogService.AFROG, parameters, false);
    assertExecutableIfAbsolute();
    Path work = Files.createTempDirectory("xiezhi-afrog-");
    Path pocs = Files.createDirectory(work.resolve("pocs"));
    Path output = work.resolve("result.json");
    try {
      for (int index = 0; index < selected.size(); index++) {
        Path source = selected.get(index).file();
        String extension = source.getFileName().toString().toLowerCase(Locale.ROOT).endsWith(".yml") ? ".yml" : ".yaml";
        Files.copy(source, pocs.resolve(String.format(Locale.ROOT, "%03d%s", index, extension)), StandardCopyOption.COPY_ATTRIBUTES);
      }
      List<String> command = buildCommand(targetUri, pocs, output);
      observer.command(command);
      ProcessBuilder builder = new ProcessBuilder(command).directory(work.toFile()).redirectErrorStream(true);
      Process process = ProcessEnvironmentSanitizer.sanitize(builder).start();
      String stdout = waitFor(process, observer, "Afrog 正在执行已选择的 PoC");
      if (process.exitValue() != 0) {
        throw new ApiException("Afrog 执行失败，退出码 " + process.exitValue() + "：" + abbreviate(stdout, 500));
      }
      observer.progressPercent(100d, "Afrog 扫描完成，正在解析结果");
      return parseOutput(targetUri, selected, readJson(output));
    } finally {
      deleteTree(work);
    }
  }

  List<String> buildCommand(URI target, Path pocsDirectory, Path jsonOutput) {
    return List.of(
        executable,
        "-t",
        target.toString(),
        "-P",
        pocsDirectory.toString(),
        "-json",
        jsonOutput.toString(),
        "-disable-output-html",
        "-disable-update-check",
        "-curated",
        "off",
        "-concurrency",
        "5",
        "-rate-limit",
        "20",
        "-req-limit-per-target",
        "10",
        "-timeout",
        "10",
        "-retries",
        "0",
        "-no-color",
        "-silent");
  }

  ToolExecutionResult parseOutput(
      URI expectedTarget,
      List<ScannerPocSelectionService.SelectedPoc> selected,
      String json) {
    List<FindingDraft> findings = new ArrayList<>();
    List<Map<String, Object>> matches = new ArrayList<>();
    Map<String, ScannerPocSelectionService.SelectedPoc> allowed = new LinkedHashMap<>();
    selected.forEach(item -> allowed.put(item.externalId(), item));
    try {
      JsonNode root = json == null || json.isBlank() ? objectMapper.createArrayNode() : objectMapper.readTree(json);
      List<JsonNode> items = new ArrayList<>();
      if (root.isArray()) root.forEach(items::add);
      else if (root.path("results").isArray()) root.path("results").forEach(items::add);
      for (JsonNode item : items) {
        // Afrog 3.x 将命中信息放在 pocinfo 子节点（id/infoname/infoseg/…），
        // 旧版放顶层 id + info.*。这里做兼容取读，避免取到空 id 而被误判为"未选择的 PoC"。
        JsonNode poc = item.path("pocinfo");
        String id = poc.path("id").asText(item.path("id").asText(""));
        if (!allowed.containsKey(id)) throw new ApiException("Afrog 返回了未选择的 PoC 结果：" + id);
        String matched = item.path("fulltarget").asText(item.path("target").asText(""));
        assertAuthorized(expectedTarget, matched);
        ScannerPocSelectionService.SelectedPoc selectedPoc = allowed.get(id);
        JsonNode info = poc.has("infoname") || poc.has("infoseg") || poc.has("infodescription")
            ? poc
            : item.path("info");
        String name = info.path("infoname").asText(info.path("name").asText(selectedPoc.name()));
        String severity = normalizeSeverity(
            info.path("infoseg").asText(info.path("severity").asText(selectedPoc.severity())));
        if (findings.size() < MAX_FINDINGS) {
          findings.add(
              new FindingDraft(
                  name,
                  severity,
                  info.path("infodescription")
                      .asText(info.path("description").asText("Afrog PoC 在授权目标上匹配到潜在安全问题，需人工确认。")),
                  "poc=" + id + "; target=" + matched,
                  "依据 PoC 引用与厂商公告确认影响，修复后使用同一 PoC 复测。",
                  selectedPoc.vulnerabilityCode()));
        }
        matches.add(Map.of("pocId", id, "name", name, "severity", severity, "target", matched));
      }
    } catch (ApiException ex) {
      throw ex;
    } catch (Exception ex) {
      throw new ApiException("无法解析 Afrog JSON 扫描结果");
    }
    Map<String, Object> data = new LinkedHashMap<>();
    data.put("selectedPocCount", selected.size());
    data.put("matchCount", matches.size());
    data.put("matches", matches);
    return new ToolExecutionResult("Afrog 扫描完成，匹配 " + matches.size() + " 项潜在问题", data, findings);
  }

  private String waitFor(Process process, ToolExecutionObserver observer, String operation) throws Exception {
    ExecutorService reader = Executors.newSingleThreadExecutor();
    Future<String> output = reader.submit(() -> readLimited(process));
    try {
      long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(timeoutSeconds);
      while (!process.waitFor(250, TimeUnit.MILLISECONDS)) {
        observer.heartbeat(operation);
        if (observer.isCancellationRequested()) {
          process.destroyForcibly();
          throw new ApiException("任务已取消");
        }
        if (System.nanoTime() >= deadline) {
          process.destroyForcibly();
          throw new ApiException("Afrog 扫描超过 " + timeoutSeconds + " 秒，已强制终止");
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
    try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
      String line;
      while ((line = reader.readLine()) != null) {
        if (output.length() + line.length() > MAX_OUTPUT_CHARS) {
          process.destroyForcibly();
          throw new ApiException("Afrog 输出超过安全大小限制");
        }
        output.append(line).append('\n');
      }
    }
    return output.toString();
  }

  private String readJson(Path file) throws Exception {
    if (!Files.exists(file)) return "[]";
    long size = Files.size(file);
    if (size > MAX_JSON_BYTES) throw new ApiException("Afrog JSON 结果超过安全大小限制");
    return Files.readString(file, StandardCharsets.UTF_8);
  }

  private void assertAuthorized(URI expected, String actual) {
    try {
      URI value = URI.create(actual.contains("://") ? actual : expected.getScheme() + "://" + actual);
      int expectedPort = expected.getPort() > 0 ? expected.getPort() : "https".equalsIgnoreCase(expected.getScheme()) ? 443 : 80;
      int actualPort = value.getPort() > 0 ? value.getPort() : "https".equalsIgnoreCase(value.getScheme()) ? 443 : 80;
      if (value.getHost() == null || !value.getHost().equalsIgnoreCase(expected.getHost()) || actualPort != expectedPort) {
        throw new ApiException("Afrog 返回了授权范围外的匹配目标：" + actual);
      }
    } catch (IllegalArgumentException ex) {
      throw new ApiException("Afrog 返回的匹配目标格式无效");
    }
  }

  private String normalizeSeverity(String value) {
    String severity = value == null ? "" : value.toUpperCase(Locale.ROOT);
    return Set.of("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO").contains(severity) ? severity : "INFO";
  }

  private void assertExecutableIfAbsolute() {
    Path path = Path.of(executable);
    if (path.isAbsolute() && !Files.isRegularFile(path)) throw new ApiException("未找到 Afrog 可执行文件：" + path);
  }

  private void deleteTree(Path root) {
    if (root == null || !Files.exists(root)) return;
    try (var paths = Files.walk(root)) {
      paths.sorted(Comparator.reverseOrder()).forEach(path -> {
        try { Files.deleteIfExists(path); } catch (Exception ignored) { }
      });
    } catch (Exception ignored) { }
  }

  private String abbreviate(String value, int max) {
    String clean = value == null ? "" : value.replaceAll("\\s+", " ").trim();
    return clean.length() <= max ? clean : clean.substring(0, max) + "…";
  }
}
