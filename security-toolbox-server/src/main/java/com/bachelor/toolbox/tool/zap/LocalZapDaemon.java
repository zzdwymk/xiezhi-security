package com.bachelor.toolbox.tool.zap;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.common.ProcessEnvironmentSanitizer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Production {@link ZapDaemon} that drives a locally-spawned OWASP ZAP headless daemon over its
 * JSON REST API. A random per-launch API key is generated in memory and never persisted; the daemon
 * binds to loopback only. Application secrets are scrubbed from the child environment so they are
 * never inherited by the external tool.
 */
final class LocalZapDaemon implements ZapDaemon {
  private static final Logger LOGGER = LoggerFactory.getLogger(LocalZapDaemon.class);
  private static final SecureRandom RANDOM = new SecureRandom();

  private volatile String executable;
  private final String host;
  private final int port;
  private final Duration startupTimeout;
  private final ExecutorService reader;
  private final HttpClient httpClient;
  private final ObjectMapper objectMapper;
  private final String apiKey;
  private volatile Process process;
  private final Set<String> fuzzReceipts = ConcurrentHashMap.newKeySet();

  LocalZapDaemon(String executable, String host, int port, Duration startupTimeout) {
    this.executable = executable;
    this.host = host;
    this.port = port;
    this.startupTimeout = startupTimeout;
    this.reader = Executors.newSingleThreadExecutor(r -> new Thread(r, "zap-daemon"));
    this.httpClient =
        HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .followRedirects(HttpClient.Redirect.NEVER)
            .build();
    this.objectMapper = new ObjectMapper();
    byte[] key = new byte[24];
    RANDOM.nextBytes(key);
    this.apiKey = Base64.getUrlEncoder().withoutPadding().encodeToString(key);
  }

  @Override
  public synchronized void start() throws Exception {
    if (isAlive()) {
      awaitReady();
      return;
    }
    cleanupZombieZapProcesses(port);
    this.executable = resolveExecutable(this.executable);
    ensureExecutable();
    Path logFile = Files.createTempFile("zap-daemon-", ".log");
    String[] args =
        new String[] {
          "-daemon",
          "-host",
          host,
          "-port",
          Integer.toString(port),
          "-config",
          "api.key=" + apiKey,
          "-config",
          "api.addrs.addr.name=*",
          "-config",
          "api.addrs.addr.regex=true",
          "-config",
          "api.addrs.addr.enabled=true",
        };
    String[] commandBuilder = buildCommand(executable, args);
    ProcessBuilder builder = new ProcessBuilder(commandBuilder).redirectErrorStream(true);
    Path exePath = Path.of(executable);
    if (Files.isRegularFile(exePath) && exePath.getParent() != null) {
      builder.directory(exePath.getParent().toFile());
    }
    ProcessEnvironmentSanitizer.sanitize(builder);
    builder.redirectOutput(logFile.toFile());
    builder.redirectError(logFile.toFile());
    reader.submit(() -> drainLog(logFile));
    LOGGER.info(
        "启动 OWASP ZAP daemon exe={} host={} port={}",
        commandBuilder.length > 0 ? commandBuilder[0] : executable, host, port);
    try {
      process = builder.start();
    } catch (Exception ex) {
      throw new ApiException("无法启动 ZAP daemon: " + executable);
    }
    awaitReady();
  }

  private String resolveExecutable(String exe) {
    if (exe != null && !exe.isBlank() && !"zap".equalsIgnoreCase(exe.trim())) {
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
    searchRoots.add(Path.of("D:\\stbtools"));
    searchRoots.add(Path.of("D:\\tools"));

    boolean isWin = System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("win");
    List<String> names = isWin ? List.of("zap.bat", "zap.exe", "zap.sh") : List.of("zap.sh", "zaproxy", "zap");
    for (Path root : searchRoots) {
      try {
        if (!Files.isDirectory(root)) continue;
        Path zapDir = root.resolve("zap");
        if (Files.isDirectory(zapDir)) {
          for (String name : names) {
            Path p = zapDir.resolve(name);
            if (Files.isRegularFile(p)) return p.toAbsolutePath().normalize().toString();
          }
          try (var stream = Files.list(zapDir)) {
            var found = stream.filter(Files::isDirectory).flatMap(sub -> names.stream().map(sub::resolve)).filter(Files::isRegularFile).findFirst();
            if (found.isPresent()) return found.get().toAbsolutePath().normalize().toString();
          } catch (Exception ignored) {}
        }
      } catch (Exception ignored) {}
    }
    return exe;
  }

  // Windows 上的 .bat/.cmd 需要经 cmd.exe 才能真正启动（JVM 不会直接执行批处理），
  // 其余（zap.sh / 原生可执行文件）直接调用。
  private static String[] buildCommand(String executable, String[] args) {
    String lower = executable.toLowerCase(Locale.ROOT);
    boolean isWindows =
        System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("win");
    boolean isWindowsBat =
        isWindows && (lower.endsWith(".bat") || lower.endsWith(".cmd"));
    if (!isWindowsBat) {
      String[] cmd = new String[args.length + 1];
      cmd[0] = executable;
      System.arraycopy(args, 0, cmd, 1, args.length);
      return cmd;
    }
    String[] cmd = new String[args.length + 3];
    cmd[0] = "cmd.exe";
    cmd[1] = "/c";
    cmd[2] = executable;
    System.arraycopy(args, 0, cmd, 3, args.length);
    return cmd;
  }

  private void drainLog(Path logFile) {
    try {
      if (!Files.exists(logFile)) return;
      try (var lines = Files.lines(logFile)) {
        lines.forEach(line -> LOGGER.debug("[zap] {}", line));
      }
    } catch (Exception ignored) {
    }
  }

  private void ensureExecutable() {
    Path path = Path.of(executable);
    if (path.isAbsolute() && !Files.isRegularFile(path)) {
      throw new ApiException("未找到 ZAP 可执行文件: " + path);
    }
  }

  private boolean isAlive() {
    Process current = process;
    return current != null && current.isAlive();
  }

  private void awaitReady() throws Exception {
    long deadline = System.nanoTime() + startupTimeout.toNanos();
    while (System.nanoTime() < deadline) {
      if (isReady()) {
        return;
      }
      if (!isAlive()) {
        throw new ApiException("ZAP daemon 进程已退出，无法就绪");
      }
      Thread.sleep(500);
    }
    throw new ApiException("ZAP daemon 在 " + startupTimeout.toSeconds() + " 秒内未就绪");
  }

  @Override
  public boolean isReady() {
    try {
      JsonNode version = getJsonRequired("core/view/version", Map.of());
      return version != null && version.path("version").isTextual();
    } catch (Exception ex) {
      return false;
    }
  }

  @Override
  public void includeInScope(URI target) throws Exception {
    String contextName = contextName();
    getJsonRequired("context/action/newContext", Map.of("contextName", contextName));
    String origin = target.getScheme() + "://" + zone(target);
    getJsonRequired(
        "context/action/includeInContext",
        Map.of("contextName", contextName, "regex", escape(origin)));
  }

  // 该 daemon 实例复用的默认上下文名：与 host/端口绑定，认证与范围共用同一上下文。
  private String contextName() {
    return "xiezhi-" + Integer.toHexString((host + port).hashCode() & 0x7fffffff);
  }

  @Override
  public void configureFormAuthentication(FormAuthSpec spec) throws Exception {
    if (spec == null) {
      return;
    }
    String contextName = spec.contextName() == null || spec.contextName().isBlank()
        ? contextName()
        : spec.contextName();
    String authType = spec.authType() == null ? "form" : spec.authType().toLowerCase(Locale.ROOT);
    String authMethodName;
    String config =
        "loginPageUrl=" + urlEncoded(spec.loginPageUrl())
            + "&loginRequestUrl=" + urlEncoded(spec.loginRequestUrl());
    // 认证方式映射：form=表单；basic/http=HTTP Basic；cookie/script=脚本式；ntlm=NTLM。
    // ZAP 各版本的 auth 方法/参数名存在差异，任一步失败都不阻塞，退化为未认证扫描。
    switch (authType) {
      case "basic", "http", "ntlm" -> {
        authMethodName = "httpBasedAuthentication";
        config = "hostname=" + host + "&port=" + port;
      }
      case "cookie", "script" -> authMethodName = "scriptBasedAuthentication";
      default -> authMethodName = "formBasedAuthentication";
    }
    try {
      getJsonRequired(
          "context/action/setAuthenticationMethod",
          Map.of(
              "contextName", contextName,
              "authMethodName", authMethodName,
              "authMethodConfigParams", config));
      getJsonRequired(
          "context/action/setSessionManagementMethod",
          Map.of(
              "contextName", contextName,
              "sessionManagementMethodName", "httpBasedSessionManagement"));
      getJsonRequired(
          "authentication/action/setAuthenticationCredentials",
          Map.of(
              "contextName", contextName,
              "credentials", spec.postData() == null ? "" : spec.postData()));
    } catch (Exception ex) {
      LOGGER.warn("ZAP 认证配置未完全生效（authType={}），将退化为未认证扫描: {}", authType, ex.getMessage());
    }
  }

  private static String urlEncoded(String value) {
    if (value == null) {
      return "";
    }
    try {
      return URI.create(value).toString();
    } catch (Exception ex) {
      return value;
    }
  }

  @Override
  public String startSpider(URI target) throws Exception {
    Map<String, String> params = new LinkedHashMap<>();
    params.put("url", target.toString());
    params.put("recurse", "true");
    params.put("maxChildren", "0");
    JsonNode json = getJsonRequired("spider/action/scan", params);
    JsonNode scan = json.get("scan");
    if (scan == null || !scan.isTextual() || scan.asText().isBlank()) {
      throw new ApiException("ZAP 未能启动页面探测，本次检测未完成，请重试");
    }
    return scan.asText();
  }

  @Override
  public int spiderProgress(String taskId) throws Exception {
    return (int) status("spider/view/status", taskId);
  }

  @Override
  public void startAjaxSpider(URI target) throws Exception {
    getJsonRequired("ajaxSpider/action/scanRun", Map.of("url", target.toString()));
  }

  @Override
  public String ajaxSpiderState() throws Exception {
    String state = getJsonRequired("ajaxSpider/view/status", Map.of()).path("status").asText("");
    if (!List.of("running", "stopped").contains(state)) {
      throw new ApiException("ZAP 未返回有效的动态页面探测进度，无法确认检测是否完成");
    }
    return state;
  }

  @Override
  public String startFuzz(FuzzSpec spec) throws Exception {
    if (spec == null) throw new ApiException("缺少单次参数变异请求参数");
    // Bundled ZAP 2.17.0 / fuzz 13.16.0 has no fuzzer REST implementor. CoreAPI really
    // registers sendRequest(request, followRedirects), returning one HTTP message per response.
    JsonNode json = postJsonRequired("core/action/sendRequest",
        Map.of("request", spec.requestMessage(), "followRedirects", "false"));
    JsonNode messages = json.path("sendRequest");
    if (!messages.isArray() || messages.size() != 1
        || !messages.get(0).path("requestHeader").asText("").startsWith(spec.method() + " ")
        || !messages.get(0).path("responseHeader").asText("")
            .matches("(?s)^HTTP/[0-9.]+ [1-5][0-9]{2}(?:[ \\r\\n].*)?$")) {
      throw new ApiException("ZAP 未返回完整的单次参数变异响应，不能确认检测完成");
    }
    String receipt = "request-" + UUID.randomUUID();
    fuzzReceipts.add(receipt);
    return receipt;
  }

  @Override
  public String fuzzStatus(String fuzzId) throws Exception {
    if (fuzzId == null || !fuzzReceipts.contains(fuzzId)) {
      throw new ApiException("不存在已确认响应的参数变异请求记录");
    }
    // PassiveScanApi in bundled pscan 0.6.0 registers this view; errors are not completion.
    long remaining = passiveScanRemaining();
    return (remaining == 0 ? "stopped" : "running") + ";id=" + fuzzId + ";requests=1";
  }

  @Override
  public long passiveScanRemaining() throws Exception {
    String remaining = getJsonRequired("pscan/view/recordsToScan", Map.of()).path("recordsToScan").asText("");
    if (!remaining.matches("0|[1-9][0-9]{0,9}")) {
      throw new ApiException("ZAP 被动检查状态无效，不能确认检测完成");
    }
    return Long.parseLong(remaining);
  }

  private double status(String path, String taskId) throws Exception {
    Map<String, String> params = new LinkedHashMap<>();
    params.put("scanId", taskId);
    JsonNode json = getJsonRequired(path, params);
    String text = json.path("status").asText("");
    if (!text.matches("(?:[0-9]|[1-9][0-9]|100)")) {
      throw new ApiException("ZAP 未返回有效的检测进度，无法确认检测是否完成，请重试");
    }
    return Integer.parseInt(text);
  }

  @Override
  public void stopSpider(String taskId) throws Exception {
    getJsonRequired("spider/action/stop", Map.of("scanId", taskId));
  }

  @Override
  public String startActiveScan(URI target) throws Exception {
    return startActiveScan(target, null);
  }

  @Override
  public String startActiveScan(URI target, String scanPolicyName) throws Exception {
    return startActiveScan(target, scanPolicyName, null, true);
  }

  @Override
  public void accessUrl(URI target) throws Exception {
    JsonNode messages = getJsonRequired("core/action/accessUrl",
        Map.of("url", target.toString(), "followRedirects", "false")).path("accessUrl");
    if (!messages.isArray() || messages.size() != 1
        || !messages.get(0).path("responseHeader").asText("")
            .matches("(?s)^HTTP/[0-9.]+ [1-5][0-9]{2}(?:[ \\r\\n].*)?$")) {
      throw new ApiException("未收到目标网站的有效响应，本次检测未完成。请确认目标已开机、网站已启动且地址可访问后重试");
    }
  }

  @Override
  public String startActiveScan(URI target, String scanPolicyName, String strength, boolean recurse)
      throws Exception {
    if (strength != null) configureAttackStrength(scanPolicyName, strength);
    Map<String, String> params = new LinkedHashMap<>();
    params.put("url", target.toString());
    params.put("recurse", Boolean.toString(recurse));
    params.put("inScopeOnly", "false");
    if (scanPolicyName != null && !scanPolicyName.isBlank()) {
      params.put("scanPolicyName", scanPolicyName);
    }
    JsonNode json = getJsonRequired("ascan/action/scan", params);
    String scanId = json.path("scan").asText("");
    if (scanId.isBlank()) throw new ApiException("ZAP 未返回主动扫描编号，扫描未启动");
    return scanId;
  }

  private void configureAttackStrength(String scanPolicyName, String strength) throws Exception {
    if (!List.of("LOW", "MEDIUM", "HIGH", "INSANE").contains(strength)) {
      throw new ApiException("不支持的 ZAP 攻击强度");
    }
    Map<String, String> policyParams = new LinkedHashMap<>();
    if (scanPolicyName != null && !scanPolicyName.isBlank()) policyParams.put("scanPolicyName", scanPolicyName);
    JsonNode scanners = getJsonRequired("ascan/view/scanners", policyParams).path("scanners");
    if (!scanners.isArray() || scanners.isEmpty()) {
      throw new ApiException("ZAP 没有可用的主动扫描规则，扫描未启动");
    }
    for (JsonNode scanner : scanners) {
      String id = scanner.path("id").asText("");
      if (!id.matches("[0-9]+")) throw new ApiException("ZAP 主动扫描规则编号无效，扫描未启动");
      Map<String, String> params = new LinkedHashMap<>(policyParams);
      params.put("id", id);
      params.put("attackStrength", strength);
      // Change strength only; preserve every rule's enabled state and alert threshold.
      getJsonRequired("ascan/action/setScannerAttackStrength", params);
    }
  }

  @Override
  public int activeScanProgress(String scanId) throws Exception {
    return (int) status("ascan/view/status", scanId);
  }

  @Override
  public ScanActivity activeScanActivity(String scanId) {
    if (scanId == null || scanId.isBlank()) return null;
    Long requestCount = null;
    String state = null;
    List<String> runningRules = new ArrayList<>();
    try {
      JsonNode scans = requiredJson("ascan/view/scans",
          httpGetJson("ascan/view/scans", Map.of(), Duration.ofSeconds(2))).path("scans");
      if (scans.isArray()) {
        for (JsonNode scan : scans) {
          if (!scanId.equals(scan.path("id").asText(""))) continue;
          String count = scan.path("reqCount").asText("");
          if (count.matches("0|[1-9][0-9]{0,17}")) requestCount = Long.parseLong(count);
          String observedState = scan.path("state").asText("");
          if (observedState.matches("[A-Z_]{1,40}")) state = observedState;
          break;
        }
      }
    } catch (InterruptedException ex) {
      Thread.currentThread().interrupt();
      return null;
    } catch (Exception ignored) {
      // Optional activity must not replace the authoritative status query.
    }
    try {
      JsonNode progress = requiredJson("ascan/view/scanProgress",
          httpGetJson("ascan/view/scanProgress", Map.of("scanId", scanId), Duration.ofSeconds(2)))
          .path("scanProgress");
      if (progress.isArray()) {
        for (JsonNode host : progress) {
          JsonNode plugins = host.path("HostProcess");
          if (!plugins.isArray()) continue;
          for (JsonNode plugin : plugins) {
            // ZAP 2.17 ApiResponseList serializes these as positional values:
            // name, id, quality, status, timeInMs, reqCount, alertCount.
            JsonNode values = plugin.path("Plugin");
            if (!values.isArray() || values.size() < 7) continue;
            if (!values.get(3).asText("").matches("(?:[0-9]|[1-9][0-9])%")) continue;
            String name = values.get(0).asText("").replaceAll("[\\p{Cntrl}]", " ").trim();
            if (!name.isBlank() && runningRules.size() < 8) {
              runningRules.add(name.length() > 160 ? name.substring(0, 160) : name);
            }
          }
        }
      }
    } catch (InterruptedException ex) {
      Thread.currentThread().interrupt();
      return null;
    } catch (Exception ignored) {
      // Keep any request count obtained even if detailed plugin progress is unavailable.
    }
    return requestCount == null && state == null && runningRules.isEmpty()
        ? null : new ScanActivity(requestCount, List.copyOf(runningRules), state);
  }

  @Override
  public void stopActiveScan(String scanId) throws Exception {
    getJsonRequired("ascan/action/stop", Map.of("scanId", String.valueOf(scanId)));
  }

  @Override
  public List<ZapAlert> alerts() throws Exception {
    JsonNode root = getJsonRequired("core/view/alerts", Map.of());
    if (!root.path("alerts").isArray()) throw new ApiException("ZAP 告警响应不完整，无法确认检查结果");
    List<ZapAlert> result = new ArrayList<>();
    for (JsonNode node : root.path("alerts")) {
      if (!node.isObject() || !node.path("url").isTextual() || node.path("url").asText().isBlank()
          || (node.path("alert").asText("").isBlank() && node.path("name").asText("").isBlank())) {
        throw new ApiException("ZAP 告警记录不完整，无法确认检查结果");
      }
      result.add(toAlert(node));
    }
    return result;
  }

  @Override
  public List<String> crawlResults(URI target) throws Exception {
    try {
      JsonNode sites = getJson("core/view/sites", Map.of());
      if (sites == null) {
        return List.of();
      }
      List<String> urls = new ArrayList<>();
      JsonNode children = sites.path("sites").path(0).path("site").path("children");
      collectUrlTree(children, urls);
      return urls;
    } catch (Exception ignored) {
      return List.of();
    }
  }

  private void collectUrlTree(JsonNode node, List<String> out) {
    if (node == null || !node.isArray()) {
      return;
    }
    for (JsonNode child : node) {
      String method = child.path("method").asText("");
      String uri = child.path("uri").asText("");
      if (uri.isBlank()) {
        uri = child.path("name").asText("");
      }
      if (!uri.isBlank()) {
        out.add(method.isBlank() ? uri : method + " " + uri);
      }
      JsonNode grandchildren = child.path("children");
      if (grandchildren.isArray() && grandchildren.size() > 0) {
        collectUrlTree(grandchildren, out);
      }
    }
  }

  @Override
  public List<String> technologies(URI target) throws Exception {
    // ZAP 各版本对“技术栈识别”REST 支持不一：优先 core/view/tech，失败退空。
    try {
      JsonNode root = getJson("core/view/tech", Map.of());
      if (root == null || !root.path("all").isArray()) {
        return List.of();
      }
      List<String> tech = new ArrayList<>();
      for (JsonNode node : root.path("all")) {
        String value = node.asText("");
        if (!value.isBlank()) {
          tech.add(value);
        }
      }
      return tech;
    } catch (Exception ex) {
      return List.of();
    }
  }

  @Override
  public boolean importOpenApi(String specUrl) throws Exception {
    if (specUrl == null || specUrl.isBlank()) {
      return false;
    }
    try {
      JsonNode root = postJson(
          "openapi/action/importUrl",
          Map.of("url", specUrl));
      return root != null && root.path("ResultCode").isTextual();
    } catch (Exception ex) {
      LOGGER.debug("ZAP OpenAPI 导入失败 specUrl={}", specUrl, ex);
      return false;
    }
  }

  private ZapAlert toAlert(JsonNode node) {
    String url = node.path("url").asText("");
    String title = node.path("alert").asText("");
    if (title.isBlank()) {
      title = node.path("name").asText("");
    }
    String risk = node.path("risk").path("desc").asText(node.path("risk").asText(""));
    if (risk.isBlank()) {
      risk = node.path("riskdesc").asText("");
    }
    String cwe = node.path("cweid").asText("");
    int sourceId = node.path("sourceid").asInt(0);
    return new ZapAlert(
        url,
        title,
        normalizeRisk(risk),
        node.path("confidence").path("desc").asText(""),
        cwe.isBlank() ? null : "CWE-" + cwe,
        node.path("description").asText(""),
        sourceId);
  }

  private String normalizeRisk(String risk) {
    String upper = risk == null ? "" : risk.toUpperCase(Locale.ROOT);
    if (upper.contains("CRITICAL")) return "CRITICAL";
    if (upper.contains("HIGH")) return "HIGH";
    if (upper.contains("MEDIUM")) return "MEDIUM";
    if (upper.contains("LOW")) return "LOW";
    return "INFO";
  }

  @Override
  public void kill() throws Exception {
    Process current = process;
    if (current != null) {
      try {
        current.descendants().forEach(ProcessHandle::destroyForcibly);
      } catch (Exception ignored) {
      }
      current.destroyForcibly();
      process = null;
    }
    reader.shutdownNow();
  }

  private void cleanupZombieZapProcesses(int targetPort) {
    try {
      ProcessHandle.allProcesses()
          .filter(
              ph -> {
                try {
                  String cmd = ph.info().commandLine().orElse("");
                  return cmd.contains("zap") && cmd.contains(Integer.toString(targetPort));
                } catch (Exception ignored) {
                  return false;
                }
              })
          .forEach(
              ph -> {
                try {
                  LOGGER.warn("检测到遗留的 ZAP 进程 pid={}，强制清理以释放端口 {}", ph.pid(), targetPort);
                  ph.destroyForcibly();
                } catch (Exception ignored) {
                }
              });
    } catch (Exception ignored) {
    }
  }

  @Override
  public void close() throws Exception {
    if (isAlive()) {
      try {
        getJsonRequiredSilent("shutdown/action/shutdown");
        process.waitFor(3, TimeUnit.SECONDS);
      } catch (Exception ignored) {
      }
    }
    kill();
  }

  private void getJsonRequiredSilent(String path) {
    try {
      getJsonRequired(path, Map.of());
    } catch (Exception ignored) {
    }
  }

  private JsonNode getJson(String path, Map<String, String> params) {
    try {
      return getJsonRequired(path, params);
    } catch (Exception ex) {
      LOGGER.debug("ZAP REST 调用失败 path={}", path, ex);
      return null;
    }
  }

  private JsonNode getJsonRequired(String path, Map<String, String> params) throws Exception {
    return requiredJson(path, httpGetJson(path, params));
  }

  private JsonNode requiredJson(String path, HttpResponse<String> response) throws Exception {
    JsonNode json = null;
    try { json = objectMapper.readTree(response.body()); } catch (Exception ignored) {}
    if (response.statusCode() != 200) {
      throw new ApiException("ZAP REST 调用失败（" + path + "），HTTP " + response.statusCode() + publicErrorCode(json));
    }
    if (json == null) throw new ApiException("无法解析 ZAP REST 响应（" + path + "）");
    if (json.has("code")) throw new ApiException("ZAP REST 返回错误（" + path + "）" + publicErrorCode(json));
    return json;
  }

  private String publicErrorCode(JsonNode json) {
    String code = json == null ? "" : json.path("code").asText("").toUpperCase(Locale.ROOT);
    return List.of("URL_NOT_FOUND", "DOES_NOT_EXIST", "BAD_ACTION", "BAD_VIEW", "MISSING_PARAMETER",
        "ILLEGAL_PARAMETER", "ALREADY_EXISTS", "NO_IMPLEMENTOR", "BAD_FORMAT", "INTERNAL_ERROR")
        .contains(code) ? "，" + code : "";
  }

  private JsonNode postJson(String path, Map<String, String> params) {
    try {
      return objectMapper.readTree(postBody(path, params));
    } catch (Exception ex) {
      return null;
    }
  }

  private JsonNode postJsonRequired(String path, Map<String, String> params) throws Exception {
    StringBuilder form = new StringBuilder("apikey=").append(apiKey);
    for (Map.Entry<String, String> entry : params.entrySet()) {
      form.append('&').append(entry.getKey()).append('=').append(enc(entry.getValue()));
    }
    return requiredJson(path, httpPostJson(path, form.toString()));
  }

  private String postBody(String path, Map<String, String> params) throws Exception {
    StringBuilder query = new StringBuilder("apikey=").append(apiKey);
    if (params != null) {
      for (Map.Entry<String, String> entry : params.entrySet()) {
        query.append('&').append(entry.getKey()).append('=').append(enc(entry.getValue()));
      }
    }
    return postBodyRaw(path, query.toString());
  }

  private String postBodyRaw(String path, String rawBody) throws Exception {
    return httpPostJson(path, rawBody).body();
  }

  private HttpResponse<String> httpPostJson(String path, String rawBody) throws Exception {
    URI uri = URI.create(
        "http://" + host + ":" + port + "/json/" + stripLeadingSlash(path));
    HttpRequest request =
        HttpRequest.newBuilder(uri)
            .timeout(Duration.ofSeconds(30))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .POST(HttpRequest.BodyPublishers.ofString(rawBody, StandardCharsets.UTF_8))
            .build();
    return httpClient.send(request, HttpResponse.BodyHandlers.ofString());
  }

  private HttpResponse<String> httpGetJson(String path, Map<String, String> params) throws Exception {
    return httpGetJson(path, params, Duration.ofSeconds(30));
  }

  private HttpResponse<String> httpGetJson(String path, Map<String, String> params, Duration timeout) throws Exception {
    StringBuilder query = new StringBuilder("apikey=").append(apiKey);
    if (params != null) {
      for (Map.Entry<String, String> entry : params.entrySet()) {
        query.append('&').append(entry.getKey()).append('=').append(enc(entry.getValue()));
      }
    }
    URI uri = URI.create("http://" + host + ":" + port + "/json/" + stripLeadingSlash(path) + "?" + query);
    HttpRequest request = HttpRequest.newBuilder(uri).timeout(timeout).GET().build();
    return httpClient.send(request, HttpResponse.BodyHandlers.ofString());
  }

  private String stripLeadingSlash(String path) {
    return path.startsWith("/") ? path.substring(1) : path;
  }

  private String enc(String value) {
    return URLEncoder.encode(value, StandardCharsets.UTF_8);
  }

  private String zone(URI uri) {
    int port = uri.getPort();
    String base = uri.getHost().toLowerCase(Locale.ROOT);
    boolean defaultPort =
        ("http".equalsIgnoreCase(uri.getScheme()) && port == 80)
            || ("https".equalsIgnoreCase(uri.getScheme()) && port == 443);
    if (port > 0 && !defaultPort) {
      base = base + ":" + port;
    }
    return base;
  }

  /** Escapes a literal origin so it is treated as a plain regex by ZAP's context include. */
  private String escape(String value) {
    return value
        .replace("\\", "\\\\")
        .replace(".", "\\.")
        .replace("+", "\\+")
        .replace("*", "\\*")
        .replace("?", "\\?")
        .replace("(", "\\(")
        .replace(")", "\\)")
        .replace("[", "\\[")
        .replace("]", "\\]")
        .replace("{", "\\{")
        .replace("}", "\\}")
        .replace("|", "\\|");
  }
}
