package com.bachelor.toolbox.tool;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.common.ProcessEnvironmentSanitizer;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.TargetPolicyService;
import com.bachelor.toolbox.target.WebTargetResolver;
import com.bachelor.toolbox.vulnerability.ScannerPocCatalogService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.DeserializationFeature;
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
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.CancellationException;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class AfrogScanTool implements SecurityTool {
  private static final int MAX_FINDINGS = 500;
  private static final int MAX_OUTPUT_CHARS = 2 * 1024 * 1024;
  private static final int MAX_JSON_BYTES = 16 * 1024 * 1024;
  private static final Pattern SCAN_STARTED = Pattern.compile(
      "^\\[(?:INF|INFO)\\]\\s+VULN-SCAN\\s*\\|\\s*started\\s*\\|\\s*targets=(\\d+) pocs=(\\d+) tasks=(\\d+).*$");
  private static final Pattern SCAN_COMPLETED = Pattern.compile(
      "^\\[(?:INF|INFO)\\]\\s+VULN-SCAN\\s*\\|\\s*completed\\s*\\|\\s*tasks=(\\d+)/(\\d+) found=(\\d+).*$");
  private static final Pattern RESPONSE_MARKER = Pattern.compile("^\\[\\d+\\]\\[([^\\]\\r\\n]+)\\] Dumped Response$");
  private static final Pattern HTTP_STATUS = Pattern.compile("^HTTP/[0-9.]+ [1-5]\\d\\d(?: .*)?$");

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
    URI targetUri = resolveBase(target, parameters);
    List<ScannerPocSelectionService.SelectedPoc> selected =
        pocSelection.resolve(
            ScannerPocCatalogService.AFROG, WebTargetResolver.scanParameters(parameters), false);
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
      ToolExecutionResult result = parseCompletedOutput(targetUri, selected, output, stdout);
      assertNotCancelled(observer);
      observer.progressPercent(100d, "Afrog 扫描完成，已核验执行结果");
      return result;
    } finally {
      deleteTree(work);
    }
  }

  /** 优先采用预解析基址，否则回退到授权目标默认 http(s) 基址。 */
  private URI resolveBase(AuthorizedTarget target, Map<String, Object> parameters) {
    List<URI> bases = WebTargetResolver.basesFromParameters(parameters);
    if (!bases.isEmpty()) return bases.get(0);
    return policy.validatedHttpUri(target);
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
        // Completed task counts alone include failed network requests in Afrog 3.5.7.
        // Debug emits the PoC ID and actual response, which we reduce to evidence below.
        "-debug");
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
      if (json == null || json.isBlank()) {
        throw new ApiException("Afrog 检测结果为空，无法确认检测是否完成。请重试。");
      }
      JsonNode root = objectMapper.reader()
          .with(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
          .with(com.fasterxml.jackson.core.JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
          .readTree(json);
      if (root.hasNonNull("error") || root.hasNonNull("errors")
          || (root.has("success") && !root.path("success").asBoolean())) {
        throw new ApiException("Afrog 返回了错误结果，本次检测未完成。请检查检测工具配置后重试。");
      }
      List<JsonNode> items = new ArrayList<>();
      if (root.isArray()) root.forEach(items::add);
      else if (root.path("results").isArray()) root.path("results").forEach(items::add);
      else throw new ApiException("Afrog 检测结果格式异常，无法确认检测结论。请检查 Afrog 版本后重试。");
      for (JsonNode item : items) {
        if (!item.isObject()) throw new ApiException("Afrog 检测结果格式异常，无法确认检测结论。请重试。");
        if (item.has("isvul") && !item.path("isvul").asBoolean()) {
          throw new ApiException("Afrog 检测结果包含未经确认的发现，无法确认检测结论。请重试。");
        }
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

  ToolExecutionResult parseCompletedOutput(
      URI expectedTarget, List<ScannerPocSelectionService.SelectedPoc> selected,
      Path output, String evidence) throws Exception {
    long startedTasks = -1;
    long loadedPocs = -1;
    long completedTasks = -1;
    long totalTasks = -1;
    long reportedFindings = -1;
    Set<String> respondedPocs = new HashSet<>();
    for (String line : evidence.split("\\R")) {
      Matcher started = SCAN_STARTED.matcher(line);
      Matcher completed = SCAN_COMPLETED.matcher(line);
      Matcher responded = RESPONSE_MARKER.matcher(line);
      if (started.matches()) {
        loadedPocs = Long.parseLong(started.group(2));
        startedTasks = Long.parseLong(started.group(3));
      } else if (completed.matches()) {
        completedTasks = Long.parseLong(completed.group(1));
        totalTasks = Long.parseLong(completed.group(2));
        reportedFindings = Long.parseLong(completed.group(3));
      } else if (responded.matches()) {
        respondedPocs.add(responded.group(1));
      }
    }
    if (loadedPocs == 0 || (loadedPocs > 0 && loadedPocs < selected.size())) {
      throw new ApiException("所选漏洞检测规则未能全部加载，本次检测不完整。请检查 Afrog 规则库后重试。");
    }
    if (loadedPocs <= 0 || startedTasks <= 0 || totalTasks != startedTasks
        || completedTasks != totalTasks || totalTasks < selected.size()) {
      throw new ApiException("未收到完整的检测执行记录，无法确认本次检测已完成。请检查 Afrog 版本和检测工具配置后重试。");
    }
    long verifiedPocs = selected.stream().filter(poc -> respondedPocs.contains(poc.externalId())).count();
    if (verifiedPocs == 0) {
      throw new ApiException("未收到目标对漏洞检测请求的有效响应，无法确认检测完成。请确认目标已开机、网站已启动，并检查网络连接；非网页检测规则也可能无法核验。");
    }
    if (verifiedPocs < selected.size()) {
      throw new ApiException("部分漏洞检测规则未收到可核验的目标响应，本次检测不完整。请检查目标连接及所选规则后重试。");
    }
    // Like Xray, Afrog omits the result file for a genuine zero-match run.
    // A reported match must never be lost by normalizing a missing file to [].
    if (reportedFindings > 0 && !Files.isRegularFile(output)) {
      throw new ApiException("Afrog 已报告检测发现，但结果文件缺失，无法读取检测结论。请重试。");
    }
    ToolExecutionResult result = parseOutput(expectedTarget, selected, readJson(output));
    if (((Number) result.data().get("matchCount")).longValue() != reportedFindings) {
      throw new ApiException("Afrog 返回的检测发现与结果文件不一致，无法确认完整结论。请重试。");
    }
    Map<String, Object> data = new LinkedHashMap<>(result.data());
    data.put("executionVerified", true);
    data.put("verifiedPocCount", verifiedPocs);
    data.put("completedTaskCount", completedTasks);
    return new ToolExecutionResult(result.summary(), data, result.findings());
  }

  String waitFor(Process process, ToolExecutionObserver observer, String operation) throws Exception {
    ExecutorService reader = Executors.newSingleThreadExecutor();
    Future<String> output = reader.submit(() -> readLimited(process));
    try {
      assertNotCancelled(observer);
      long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(timeoutSeconds);
      while (!process.waitFor(250, TimeUnit.MILLISECONDS)) {
        observer.heartbeat(operation);
        assertNotCancelled(observer);
        if (System.nanoTime() >= deadline) {
          process.destroyForcibly();
          throw new TimeoutException("Afrog 检测超过 " + timeoutSeconds + " 秒，已停止运行，检测未完成。");
        }
      }
      assertNotCancelled(observer);
      return output.get(10, TimeUnit.SECONDS);
    } finally {
      if (process.isAlive()) process.destroyForcibly();
      reader.shutdownNow();
    }
  }

  private void assertNotCancelled(ToolExecutionObserver observer) {
    if (Thread.currentThread().isInterrupted() || observer.isCancellationRequested()) {
      throw new CancellationException("Afrog 检测已取消");
    }
  }

  private String readLimited(Process process) throws Exception {
    try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
      return readExecutionEvidence(reader);
    }
  }

  String readExecutionEvidence(BufferedReader reader) throws Exception {
    StringBuilder output = new StringBuilder();
    String pendingResponse = null;
    String line;
    while ((line = reader.readLine()) != null) {
      String clean = line.replaceAll("\\u001B\\[[;\\d]*[A-Za-z]", "").trim();
      if (pendingResponse != null) {
        if (HTTP_STATUS.matcher(clean).matches()) output.append(pendingResponse).append('\n');
        pendingResponse = null;
      }
      if (RESPONSE_MARKER.matcher(clean).matches()) {
        pendingResponse = clean;
      } else if (SCAN_STARTED.matcher(clean).matches() || SCAN_COMPLETED.matcher(clean).matches()) {
        output.append(clean).append('\n');
      }
      // Do not retain debug request/response bodies or interpret their text as engine errors.
      if (output.length() > MAX_OUTPUT_CHARS) throw new ApiException("Afrog 执行记录超过安全大小限制");
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
