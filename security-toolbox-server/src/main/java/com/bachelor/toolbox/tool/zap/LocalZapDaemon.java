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

  private final String executable;
  private final String host;
  private final int port;
  private final Duration startupTimeout;
  private final ExecutorService reader;
  private final HttpClient httpClient;
  private final ObjectMapper objectMapper;
  private final String apiKey;
  private volatile Process process;

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
    String contextName = "xiezhi-" + Integer.toHexString((host + port).hashCode() & 0x7fffffff);
    getJsonRequired("context/action/newContext", Map.of("contextName", contextName));
    String origin = target.getScheme() + "://" + zone(target);
    getJsonRequired(
        "context/action/includeInContext",
        Map.of("contextName", contextName, "regex", escape(origin)));
  }

  @Override
  public String startSpider(URI target) throws Exception {
    Map<String, String> params = new LinkedHashMap<>();
    params.put("url", target.toString());
    params.put("recurse", "true");
    params.put("maxChildren", "0");
    JsonNode json = getJsonRequired("spider/action/scan", params);
    JsonNode scan = json.get("scan");
    return scan == null || !scan.isTextual() || scan.asText().isBlank() ? "" : scan.asText();
  }

  @Override
  public int spiderProgress(String taskId) throws Exception {
    return (int) status("spider/view/status", taskId);
  }

  private double status(String path, String taskId) throws Exception {
    Map<String, String> params = new LinkedHashMap<>();
    params.put("scanId", taskId);
    JsonNode json = getJsonRequired(path, params);
    String text = json.path("status").asText("0");
    try {
      return Double.parseDouble(text.isBlank() ? "0" : text);
    } catch (NumberFormatException ex) {
      return 0;
    }
  }

  @Override
  public void stopSpider(String taskId) throws Exception {
    getJsonRequired("spider/action/stop", Map.of("scanId", taskId));
  }

  @Override
  public String startActiveScan(URI target) throws Exception {
    Map<String, String> params = new LinkedHashMap<>();
    params.put("url", target.toString());
    params.put("recurse", "true");
    params.put("inScopeOnly", "false");
    JsonNode json = getJson("ascan/action/scan", params);
    JsonNode scan = json == null ? null : json.get("scan");
    return scan == null || scan.isNull() ? "" : scan.asText();
  }

  @Override
  public int activeScanProgress(String scanId) throws Exception {
    return (int) status("ascan/view/status", scanId);
  }

  @Override
  public void stopActiveScan(String scanId) throws Exception {
    getJsonRequired("ascan/action/stop", Map.of("scanId", String.valueOf(scanId)));
  }

  @Override
  public List<ZapAlert> alerts() throws Exception {
    JsonNode root = getJson("core/view/alerts", Map.of());
    if (root == null || !root.path("alerts").isArray()) {
      return List.of();
    }
    List<ZapAlert> result = new ArrayList<>();
    for (JsonNode node : root.path("alerts")) {
      result.add(toAlert(node));
    }
    return result;
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
    return new ZapAlert(
        url,
        title,
        normalizeRisk(risk),
        node.path("confidence").path("desc").asText(""),
        cwe.isBlank() ? null : "CWE-" + cwe,
        node.path("description").asText(""));
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
      current.destroyForcibly();
      process = null;
    }
    reader.shutdownNow();
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
    HttpResponse<String> response = httpGetJson(path, params);
    if (response.statusCode() != 200) {
      throw new ApiException("ZAP REST 调用失败，HTTP " + response.statusCode());
    }
    try {
      return objectMapper.readTree(response.body());
    } catch (Exception ex) {
      throw new ApiException("无法解析 ZAP REST 响应");
    }
  }

  private HttpResponse<String> httpGetJson(String path, Map<String, String> params) throws Exception {
    StringBuilder query = new StringBuilder("apikey=").append(apiKey);
    if (params != null) {
      for (Map.Entry<String, String> entry : params.entrySet()) {
        query.append('&').append(entry.getKey()).append('=').append(enc(entry.getValue()));
      }
    }
    URI uri = URI.create("http://" + host + ":" + port + "/json/" + stripLeadingSlash(path) + "?" + query);
    HttpRequest request = HttpRequest.newBuilder(uri).timeout(Duration.ofSeconds(30)).GET().build();
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