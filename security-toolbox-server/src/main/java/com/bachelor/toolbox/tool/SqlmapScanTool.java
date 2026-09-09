package com.bachelor.toolbox.tool;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.common.ProcessEnvironmentSanitizer;
import com.bachelor.toolbox.dependency.ExecutableLocator;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.TargetPolicyService;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * 受控的 SQL 注入检测工具（sqlmap）。
 *
 * <p>仅在已授权目标 host:端口 范围内对指定 URL/参数运行 sqlmap 子进程，默认仅做注入探测
 * （--batch，不启用 --dump/数据导出）。命中的注入点作为 HIGH 级 {@link FindingDraft} 提交，
 * 含可注入参数、注入类型与后端 DBMS。检测强度(level/risk)由调用方在授权范围内显式选择。
 */
@Component
public class SqlmapScanTool implements SecurityTool {
  private static final int MAX_READ_BYTES = 4 * 1024 * 1024;

  private static final Pattern INJECTION_BLOCK =
      Pattern.compile(
          "sqlmap identified the following injection point.*?(?=\\n\\[|\\n\\n\\[|\\z)",
          Pattern.DOTALL);
  private static final Pattern PARAMETER = Pattern.compile("(?m)^\\s*Parameter:\\s*(.+)$");
  private static final Pattern TYPE = Pattern.compile("(?m)^\\s*Type:\\s*(.+)$");
  private static final Pattern DBMS = Pattern.compile("(?im)back-end DBMS:\\s*(.+)");

  private final TargetPolicyService policy;
  private final ExecutableLocator locator;
  private final String configuredExecutable;
  private final long timeoutSeconds;

  public SqlmapScanTool(
      TargetPolicyService policy,
      ExecutableLocator locator,
      @Value("${toolbox.execution.sqlmap-path:sqlmap}") String configuredExecutable,
      @Value("${toolbox.execution.sqlmap-timeout-seconds:600}") long timeoutSeconds) {
    this.policy = policy;
    this.locator = locator;
    this.configuredExecutable = configuredExecutable;
    this.timeoutSeconds = timeoutSeconds;
  }

  @Override
  public String code() {
    return "sqlmap_scan";
  }

  @Override
  public String displayName() {
    return "sqlmap SQL 注入检测";
  }

  @Override
  public String description() {
    return "在授权 Web 目标上使用 sqlmap 对 URL 查询参数进行 SQL 注入探测（默认仅探测，不导出数据）";
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
    String path = Objects.toString(parameters.getOrDefault("path", ""), "").trim();
    URI uri = policy.validatedHttpUri(target, path.isBlank() ? null : path);
    String url = uri.toString();
    int level = clampInt(parameters.get("level"), 1, 5, 1);
    int risk = clampInt(parameters.get("risk"), 1, 3, 1);
    String technique = sanitizeTechnique(parameters.get("technique"));

    Path executable = requireExecutable();
    Path outputDir = Files.createTempDirectory("xiezhi-sqlmap-");
    try {
      List<String> command = new ArrayList<>();
      command.add(executable.toString());
      command.add("-u");
      command.add(url);
      command.add("--batch");
      command.add("--disable-coloring");
      command.add("--flush-session");
      command.add("--level=" + level);
      command.add("--risk=" + risk);
      if (technique != null) {
        command.add("--technique=" + technique);
      }
      command.add("--output-dir=" + outputDir);
      observer.command(command);
      observer.heartbeat("sqlmap 已启动，正在探测 SQL 注入");

      ProcessBuilder builder = ProcessEnvironmentSanitizer.sanitize(new ProcessBuilder(command));
      builder.redirectErrorStream(true);
      Process process = builder.start();
      // sqlmap 在 --batch 下不需交互输入；关闭 stdin 让任何读取立即 EOF。
      try (OutputStream stdin = process.getOutputStream()) {
        stdin.flush();
      } catch (Exception ignored) {
        // ignore
      }
      try {
        String stdout = waitForProcess(process, observer, timeoutSeconds);
        observer.progressPercent(100d, "sqlmap 完成，正在解析注入结果");
        return parseOutput(url, stdout);
      } finally {
        if (process.isAlive()) process.destroyForcibly();
      }
    } finally {
      deleteRecursive(outputDir);
    }
  }

  ToolExecutionResult parseOutput(String url, String outputText) {
    String text = outputText == null ? "" : outputText;
    Map<String, Object> data = new LinkedHashMap<>();
    data.put("url", url);
    List<FindingDraft> findings = new ArrayList<>();

    Matcher block = INJECTION_BLOCK.matcher(text);
    boolean vulnerable = block.find();
    if (vulnerable) {
      String injection = block.group();
      String parameter = firstGroup(PARAMETER, injection, "未知参数");
      List<String> types = new ArrayList<>();
      Matcher t = TYPE.matcher(injection);
      while (t.find()) {
        types.add(t.group(1).trim());
      }
      String dbms = firstGroup(DBMS, text, "未知");
      data.put("vulnerable", true);
      data.put("parameter", parameter);
      data.put("types", types);
      data.put("dbms", dbms);

      String desc =
          "sqlmap 确认目标 URL 存在 SQL 注入。可注入参数: "
              + parameter
              + "；注入类型: "
              + (types.isEmpty() ? "见证据" : String.join("、", types))
              + "；后端数据库: "
              + dbms
              + "。攻击者可借此读取/篡改数据库数据，属高危漏洞。";
      String remediation =
          "对所有进入 SQL 语句的用户输入使用参数化查询/预编译语句（Prepared Statement）；"
              + "对输入做类型与白名单校验；最小化数据库账户权限；部署 WAF 作为纵深防御。";
      findings.add(
          new FindingDraft(
              "SQL 注入漏洞（" + parameter + "）",
              "HIGH",
              desc,
              abbreviate(injection, 4000),
              remediation,
              "STB-SQLMAP-001"));
    } else {
      data.put("vulnerable", false);
    }

    String summary =
        vulnerable
            ? "sqlmap 确认存在 SQL 注入（" + findings.size() + " 处注入点）"
            : "sqlmap 未在该 URL 参数上确认 SQL 注入";
    return new ToolExecutionResult(summary, data, findings);
  }

  private Path requireExecutable() {
    Path executable =
        locator
            .find(candidates())
            .orElseThrow(() -> new ApiException("未找到已配置的 sqlmap 可执行文件"));
    if (!Files.isRegularFile(executable)) {
      throw new ApiException("未找到已配置的 sqlmap 可执行文件");
    }
    return executable.toAbsolutePath().normalize();
  }

  private List<String> candidates() {
    List<String> candidates = new ArrayList<>();
    if (configuredExecutable != null && !configuredExecutable.isBlank()) {
      candidates.add(configuredExecutable);
    }
    candidates.add("sqlmap.bat");
    candidates.add("sqlmap");
    candidates.add("sqlmap.py");
    return List.copyOf(candidates);
  }

  private String waitForProcess(Process process, ToolExecutionObserver observer, long timeout)
      throws Exception {
    ExecutorService reader = Executors.newSingleThreadExecutor();
    Future<String> output = reader.submit(() -> readLimited(process.getInputStream()));
    try {
      long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(timeout);
      while (!process.waitFor(250, TimeUnit.MILLISECONDS)) {
        observer.heartbeat("sqlmap 正在探测");
        if (observer.isCancellationRequested()) {
          process.destroyForcibly();
          process.waitFor(5, TimeUnit.SECONDS);
          throw new ApiException("任务已取消");
        }
        if (System.nanoTime() >= deadline) {
          process.destroyForcibly();
          process.waitFor(5, TimeUnit.SECONDS);
          throw new ApiException("sqlmap 探测超过 " + timeout + " 秒，已强制终止");
        }
      }
      return output.get(10, TimeUnit.SECONDS);
    } finally {
      reader.shutdownNow();
    }
  }

  private String readLimited(InputStream input) throws Exception {
    byte[] data = input.readNBytes(MAX_READ_BYTES + 1);
    if (data.length > MAX_READ_BYTES) {
      return new String(data, 0, MAX_READ_BYTES, StandardCharsets.UTF_8);
    }
    return new String(data, StandardCharsets.UTF_8);
  }

  private int clampInt(Object value, int min, int max, int fallback) {
    if (value == null) return fallback;
    try {
      int v = Integer.parseInt(value.toString().trim());
      return Math.max(min, Math.min(max, v));
    } catch (NumberFormatException ex) {
      return fallback;
    }
  }

  private String sanitizeTechnique(Object value) {
    if (value == null) return null;
    String t = value.toString().trim().toUpperCase(java.util.Locale.ROOT);
    if (t.isBlank() || !t.matches("[BEUSTQ]{1,6}")) {
      return null;
    }
    return t;
  }

  private String firstGroup(Pattern pattern, String text, String fallback) {
    Matcher m = pattern.matcher(text);
    return m.find() ? m.group(1).trim() : fallback;
  }

  private String abbreviate(String value, int max) {
    if (value == null) return "";
    String trimmed = value.strip();
    return trimmed.length() <= max ? trimmed : trimmed.substring(0, max) + "…";
  }

  private void deleteRecursive(Path dir) {
    if (dir == null) return;
    try (var stream = Files.walk(dir)) {
      stream
          .sorted((a, b) -> b.getNameCount() - a.getNameCount())
          .forEach(
              p -> {
                try {
                  Files.deleteIfExists(p);
                } catch (Exception ignored) {
                  // best-effort cleanup
                }
              });
    } catch (Exception ignored) {
      // best-effort cleanup
    }
  }
}
