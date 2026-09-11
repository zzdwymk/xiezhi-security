package com.bachelor.toolbox.tool;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.common.ProcessEnvironmentSanitizer;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.TargetPolicyService;
import com.bachelor.toolbox.target.WebTargetResolver;
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
    URI targetUri = resolveBase(target, parameters);
    List<ScannerPocSelectionService.SelectedPoc> selected =
        pocSelection.resolve(ScannerPocCatalogService.XRAY, parameters, false);
    boolean allPocs = pocSelection.selectsAll(parameters);
    String resolvedExe = resolveExecutable(executable);
    assertExecutableIfAbsolute(resolvedExe);
    Path work = Files.createTempDirectory("xiezhi-xray-");
    Path output = work.resolve("result.json");
    try {
      initializeConfig(work, resolvedExe);
      List<String> command = buildCommand(resolvedExe, targetUri, selected, output, allPocs);
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

  /** 优先采用预解析基址，否则回退到授权目标默认 http(s) 基址。 */
  private URI resolveBase(AuthorizedTarget target, Map<String, Object> parameters) {
    List<URI> bases = WebTargetResolver.basesFromParameters(parameters);
    if (!bases.isEmpty()) return bases.get(0);
    return policy.validatedHttpUri(target);
  }

  List<String> buildCommand(
      URI target, List<ScannerPocSelectionService.SelectedPoc> selected, Path jsonOutput) {
    return buildCommand(executable, target, selected, jsonOutput, false);
  }

  List<String> buildCommand(
      URI target,
      List<ScannerPocSelectionService.SelectedPoc> selected,
      Path jsonOutput,
      boolean allPocs) {
    return buildCommand(executable, target, selected, jsonOutput, allPocs);
  }

  List<String> buildCommand(
      String exe,
      URI target,
      List<ScannerPocSelectionService.SelectedPoc> selected,
      Path jsonOutput,
      boolean allPocs) {
    List<String> command = new ArrayList<>();
    command.add(exe);
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

  private static final List<String> XRAY_CONFIG_FILES =
      List.of("config.yaml", "module.xray.yaml", "plugin.xray.yaml", "xray.yaml");

  private void initializeConfig(Path work, String resolvedExe) throws Exception {
    copyConfigTemplates(work, resolvedExe);
    List<String> command = List.of(resolvedExe, "version");
    ProcessBuilder builder = new ProcessBuilder(command).directory(work.toFile()).redirectErrorStream(true);
    Process process = ProcessEnvironmentSanitizer.sanitize(builder).start();
    String stdout = waitFor(process, ToolExecutionObserver.NOOP, "正在初始化 Xray 隔离配置", 15);
    if (process.exitValue() != 0) {
      throw new ApiException("Xray 隔离配置初始化失败: " + abbreviate(stdout, 300));
    }
  }

  void copyConfigTemplates(Path work, String resolvedExe) {
    List<Path> searchDirs = new ArrayList<>();
    if (resolvedExe != null && !resolvedExe.isBlank()) {
      try {
        Path exePath = Path.of(resolvedExe);
        if (exePath.isAbsolute() && exePath.getParent() != null) {
          searchDirs.add(exePath.getParent());
        }
      } catch (Exception ignored) {}
    }
    String toolsDirVal = System.getenv("TOOLBOX_TOOLS_DIR");
    if (toolsDirVal != null && !toolsDirVal.isBlank()) {
      searchDirs.add(Path.of(toolsDirVal.trim(), "xray"));
    }
    searchRoots(searchDirs);

    for (String fileName : XRAY_CONFIG_FILES) {
      Path targetFile = work.resolve(fileName);
      boolean copied = false;
      for (Path dir : searchDirs) {
        try {
          Path candidate = dir.resolve(fileName);
          if (Files.isRegularFile(candidate)) {
            Files.copy(candidate, targetFile, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            copied = true;
            break;
          }
        } catch (Exception ignored) {}
      }
      if (!copied) {
        try (var in = getClass().getResourceAsStream("/xray/" + fileName)) {
          if (in != null) {
            Files.copy(in, targetFile, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            copied = true;
          }
        } catch (Exception ignored) {}
      }
      if (!copied) {
        String fallback = fallbackConfig(fileName);
        if (fallback != null) {
          try {
            Files.writeString(targetFile, fallback, java.nio.charset.StandardCharsets.UTF_8);
          } catch (Exception ignored) {}
        }
      }
    }
  }

  private String fallbackConfig(String fileName) {
    if ("module.xray.yaml".equals(fileName)) {
      return """
Client:
    active_paths: []
    allow_methods:
        - HEAD
        - GET
        - POST
        - PUT
        - PATCH
        - DELETE
        - OPTIONS
        - CONNECT
        - TRACE
        - MOVE
        - PROPFIND
    dial_timeout: 5
    enable_http2: false
    fail_retries: 0
    headers: {}
    max_conns_per_host: 50
    max_qps: 500
    max_redirect: 5
    max_resp_body_size: 2.097152e+06
    passive_mode: false
    pkcs12:
        Password: ""
        Path: ""
    proxy: ""
    proxy_rule: null
    read_timeout: 10
Pool:
    size: 100
Reverse:
    client:
        dns_server_ip: ""
        http_base_url: ""
        remote_server: false
        reverse_api: ""
        reverse_server_url: ""
        rmi_server_addr: ""
    db_file_path: ""
    dns:
        domain: ""
        enabled: false
        is_domain_name_server: false
        listen_ip: 0.0.0.0
        resolve:
            - record: localhost
              ttl: 60
              type: A
              value: 127.0.0.1
    http:
        enabled: false
        ip_header: ""
        listen_ip: 0.0.0.0
        listen_port: ""
    rmi:
        enabled: false
        listen_ip: 127.0.0.1
        listen_port: ""
    token: ""
""";
    }
    if ("plugin.xray.yaml".equals(fileName)) {
      return """
printer:
    disable_host_print: false
    disable_port_print: false
    disable_service_print: false
    disable_website_print: false
service-scan:
    bandwidth: 1000
    flag:
        bandwidth: bandwidth,bw
        max_service_per_host: max-srv,ms
        port: port,p
        skip_fingerprint: skip-fingerprint,sf
        skip_live: skip-live,sl
        skip_syn: skip-syn,ss
        skip_web_fingerprint: skip-web,sw
        timeout: timeout
    max_service_per_host: 0
    port: 22,80,443
    skip_fingerprint: false
    skip_live: false
    skip_syn: false
    skip_web_fingerprint: false
    timeout: 2
target-parser:
    flag:
        target: target,t
    group_size: 256
    target: ""
vuln-scan:
    config_file: config.yaml
    flag:
        config_file: config
        html_output: html-output,ho
        json_output: json_output,jo
        level: level
        log_level: log-level
        plugins: plugins
        poc: poc
        stdout: stdout
        tags: tags
        text_output: text-output,to
        webhook_output: webhook-output,wo
    html_output: ""
    json_output: ""
    level: ""
    log_level: ""
    plugins: ""
    poc: ""
    stdout: true
    tags: ""
    text_output: ""
    webhook_output: ""
""";
    }
    if ("xray.yaml".equals(fileName)) {
      return """
- name: x
  description: |-
    A command that enables all plugins.
    You can customize new commands or modify the plugins enabled by a command in the configuration file.
  enabled_plugins:
    - printer
    - service-scan
    - target-parser
    - vuln-scan
  disabled_plugins: []
  plugin_path:
    - ./plugin
  module_config: module.xray.yaml
  plugin_config: plugin.xray.yaml
""";
    }
    if ("config.yaml".equals(fileName)) {
      return """
version: 4.0
parallel: 30
http:
  proxy: ""
  dial_timeout: 5
  read_timeout: 10
  max_conns_per_host: 50
  enable_http2: false
  fail_retries: 0
  max_redirect: 5
  max_resp_body_size: 2097152
  max_qps: 500
""";
    }
    return null;
  }

  private void searchRoots(List<Path> targetList) {
    targetList.add(Path.of("tools", "xray"));
    targetList.add(Path.of("..", "tools", "xray"));
    targetList.add(Path.of("security-toolbox-web", "tools", "xray"));
    targetList.add(Path.of("..", "security-toolbox-web", "tools", "xray"));
    targetList.add(Path.of("security-toolbox-web", "desktop-release", "win-unpacked", "tools", "xray"));
    targetList.add(Path.of("..", "security-toolbox-web", "desktop-release", "win-unpacked", "tools", "xray"));
    targetList.add(Path.of("."));
    targetList.add(Path.of(".."));
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

  private void assertExecutableIfAbsolute(String pathStr) {
    Path path = Path.of(pathStr);
    if (path.isAbsolute() && !Files.isRegularFile(path)) {
      throw new ApiException("未找到 Xray 可执行文件：" + path);
    }
  }

  private String resolveExecutable(String exe) {
    if (exe != null && !exe.isBlank() && !"xray".equalsIgnoreCase(exe.trim())) {
      Path p = Path.of(exe);
      if (Files.isRegularFile(p)) {
        return p.toAbsolutePath().normalize().toString();
      }
    }
    String toolsDirVal = System.getenv("TOOLBOX_TOOLS_DIR");
    List<Path> searchRoots = new ArrayList<>();
    if (toolsDirVal != null && !toolsDirVal.isBlank()) {
      searchRoots.add(Path.of(toolsDirVal.trim()));
    }
    searchRoots.add(Path.of("tools"));
    searchRoots.add(Path.of("..", "tools"));
    searchRoots.add(Path.of("security-toolbox-web", "tools"));
    searchRoots.add(Path.of("..", "security-toolbox-web", "tools"));
    searchRoots.add(Path.of("security-toolbox-web", "desktop-release", "win-unpacked", "tools"));
    searchRoots.add(Path.of("..", "security-toolbox-web", "desktop-release", "win-unpacked", "tools"));

    boolean isWin = System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("win");
    List<String> names = isWin ? List.of("xray_windows_amd64.exe", "xray.exe") : List.of("xray");
    for (Path root : searchRoots) {
      try {
        if (!Files.isDirectory(root)) continue;
        Path xrayDir = root.resolve("xray");
        if (Files.isDirectory(xrayDir)) {
          for (String name : names) {
            Path p = xrayDir.resolve(name);
            if (Files.isRegularFile(p)) return p.toAbsolutePath().normalize().toString();
          }
        }
      } catch (Exception ignored) {}
    }
    return exe;
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
