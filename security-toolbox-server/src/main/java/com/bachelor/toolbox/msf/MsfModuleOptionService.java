package com.bachelor.toolbox.msf;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.common.ProcessEnvironmentSanitizer;
import com.bachelor.toolbox.dependency.ExecutableLocator;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * 读取单个 Metasploit 模块的 Datastore 选项（名称、类型、默认值、是否必填等），供前端在工作流
 * MSF 节点中自动回填「每个模块所需要的必要配置」。
 *
 * <p>通过 {@code msfconsole -q -x "info -j &lt;module&gt;; exit"} 拉取 JSON。RHOST/RHOSTS/
 * RPORT/LHOST/LPORT/PAYLOAD/CMD/SHELL 等坐标与载荷字段由后端在真正执行时强制固定（见
 * {@code MsfScanTool}），这里一并剔除，避免把授权边界暴露给前端改写。
 */
@Component
public class MsfModuleOptionService {
  private static final Logger log = LoggerFactory.getLogger(MsfModuleOptionService.class);

  private static final int MAX_OUTPUT_BYTES = 4 * 1024 * 1024;

  /** 与 MsfScanTool 保持一致的服务端保留键，前端不得改写。 */
  private static final Set<String> RESERVED_OPTION_KEYS =
      Set.of(
          "RHOST", "RHOSTS", "RPORT", "LHOST", "LPORT", "PAYLOAD", "CMD", "COMMAND", "SHELL",
          "CHOST", "CPORT");

  private final ExecutableLocator locator;
  private final ObjectMapper objectMapper;
  private final String configuredExecutable;
  private final long timeoutSeconds;

  /** Round 311：模块选项缓存（10 分钟，最多 500 条），避免每次请求都启动 msfconsole。 */
  private static final long CACHE_TTL_MILLIS = 10 * 60_000L;

  private static final int MAX_CACHE_ENTRIES = 500;

  private final Map<String, CachedOptions> optionsCache = new java.util.concurrent.ConcurrentHashMap<>();

  /** Round 312：按模块分锁，避免一个慢模块阻塞其它模块的读取。 */
  private final java.util.concurrent.ConcurrentHashMap<String, Object> moduleLocks =
      new java.util.concurrent.ConcurrentHashMap<>();

  /** Round 313：同时进行的 msfconsole 读取上限。 */
  private final int maxConcurrentOptions;

  private final java.util.concurrent.Semaphore optionSlots;

  @org.springframework.beans.factory.annotation.Autowired
  public MsfModuleOptionService(
      ExecutableLocator locator,
      ObjectMapper objectMapper,
      @Value("${toolbox.execution.msf-path:msfconsole}") String configuredExecutable,
      @Value("${toolbox.execution.msf-timeout-seconds:600}") long timeoutSeconds) {
    this(locator, objectMapper, configuredExecutable, timeoutSeconds, 2);
  }

  public MsfModuleOptionService(
      ExecutableLocator locator,
      ObjectMapper objectMapper,
      String configuredExecutable,
      long timeoutSeconds,
      int maxConcurrentOptions) {
    this.locator = locator;
    this.objectMapper = objectMapper;
    this.configuredExecutable = configuredExecutable;
    this.timeoutSeconds = timeoutSeconds;
    this.maxConcurrentOptions = Math.max(1, Math.min(maxConcurrentOptions, 8));
    this.optionSlots = new java.util.concurrent.Semaphore(this.maxConcurrentOptions);
  }

  /** 返回某模块的可配置选项（不含服务端保留键）。 */
  public List<ModuleOption> options(String modulePath) {
    String module = normalizeModule(modulePath);
    long now = System.currentTimeMillis();
    CachedOptions cached = optionsCache.get(module);
    if (cached != null && now - cached.cachedAtMillis < CACHE_TTL_MILLIS) {
      return cached.options;
    }
    Object moduleLock = moduleLocks.computeIfAbsent(module, key -> new Object());
    synchronized (moduleLock) {
      cached = optionsCache.get(module);
      if (cached != null && System.currentTimeMillis() - cached.cachedAtMillis < CACHE_TTL_MILLIS) {
        return cached.options;
      }
      List<ModuleOption> loaded;
      boolean acquired = false;
      try {
        // Round 313：单次 msfconsole 读取实测约 60 秒，排队等待必须覆盖这一量级，
        // 否则第三个并发请求会在 15 秒时被误判为"繁忙"（实测 3 并发时返回 400）。
        acquired = optionSlots.tryAcquire(180, TimeUnit.SECONDS);
        if (!acquired) {
          throw new ApiException("MSF 模块选项读取繁忙，请稍后重试");
        }
        loaded = loadOptions(module);
      } catch (InterruptedException interrupted) {
        Thread.currentThread().interrupt();
        throw new ApiException("MSF 模块选项读取被中断");
      } finally {
        if (acquired) optionSlots.release();
      }
      List<ModuleOption> snapshot = List.copyOf(loaded);
      if (optionsCache.size() >= MAX_CACHE_ENTRIES) {
        optionsCache.clear();
        moduleLocks.clear();
      }
      optionsCache.put(module, new CachedOptions(snapshot, System.currentTimeMillis()));
      return snapshot;
    }
  }

  /** 供测试覆写：真正启动 msfconsole 读取并解析的慢路径。 */
  List<ModuleOption> loadOptions(String module) {
    Path executable = requireExecutable();
    String script = "info -j " + module + "; exit";
    ProcessBuilder builder =
        ProcessEnvironmentSanitizer.sanitize(
            new ProcessBuilder(executable.toString(), "-q", "-x", script));
    builder.redirectErrorStream(true);
    Process process;
    try {
      process = builder.start();
    } catch (Exception ex) {
      throw new ApiException("启动 msfconsole 读取模块选项失败：" + abbrev(ex.getMessage(), 120));
    }
    try {
      String output = waitFor(process, module);
      return parse(module, output);
    } finally {
      if (process.isAlive()) process.destroyForcibly();
    }
  }

  private Path requireExecutable() {
    Set<String> candidates = new LinkedHashSet<>();
    if (configuredExecutable != null && !configuredExecutable.isBlank()) {
      candidates.add(configuredExecutable.trim());
    }
    candidates.add("msfconsole");
    candidates.add("msfconsole.bat");
    Path executable =
        locator
            .find(List.copyOf(candidates))
            .orElseThrow(() -> new ApiException("未找到 msfconsole，请先安装 MetasploitFramework"));
    if (!Files.isRegularFile(executable)) {
      throw new ApiException("未找到已配置的 msfconsole 可执行文件");
    }
    return executable.toAbsolutePath().normalize();
  }

  private String normalizeModule(String raw) {
    String module = String.valueOf(raw == null ? "" : raw).trim().toLowerCase(Locale.ROOT);
    if (module.isBlank() || module.length() > 256) {
      throw new ApiException("MSF 模块路径不合法");
    }
    if (!(module.startsWith("auxiliary/") || module.startsWith("exploit/"))) {
      throw new ApiException("仅允许 auxiliary 或 exploit 模块");
    }
    if (module.matches(".*(\\s|[;&|>`$'\"]).*")
        || module.contains("..")
        || module.contains("\\")) {
      throw new ApiException("MSF 模块路径不合法");
    }
    return module;
  }

  List<ModuleOption> parse(String module, String output) {
    JsonNode options = readOptionsJson(module, output);
    List<ModuleOption> result = new ArrayList<>();
    if (options.isArray()) {
      for (JsonNode option : options) {
        if (!option.isObject() || !option.path("name").isTextual()
            || !option.has("display_value") || !option.path("description").isTextual()) {
          throw new ApiException("MSF 模块选项数组格式无效");
        }
        addOption(result, option.path("name").asText(), option, "display_value", "description");
      }
    } else {
      Iterator<Map.Entry<String, JsonNode>> it = options.fields();
      while (it.hasNext()) {
        Map.Entry<String, JsonNode> field = it.next();
        JsonNode node = field.getValue();
        if (!node.isObject() || !node.has("required")
            || !(node.has("default") || node.has("desc") || node.has("type"))) {
          throw new ApiException("MSF 模块选项对象格式无效");
        }
        addOption(result, field.getKey(), node, "default", "desc");
      }
    }
    result.sort(
        (a, b) -> {
          if (a.required() != b.required()) return a.required() ? -1 : 1;
          return a.name().compareToIgnoreCase(b.name());
        });
    return result;
  }

  private void addOption(List<ModuleOption> result, String rawName, JsonNode node,
      String defaultField, String descriptionField) {
    String name = rawName.trim();
    JsonNode required = node.get("required");
    if (name.isBlank() || required == null || !(required.isBoolean()
        || required.isTextual() && Set.of("true", "false", "yes", "no").contains(required.asText().toLowerCase(Locale.ROOT)))) {
      throw new ApiException("MSF 模块选项名称或必填标记无效");
    }
    if (RESERVED_OPTION_KEYS.contains(name.toUpperCase(Locale.ROOT))) return;
    result.add(new ModuleOption(name, optionalText(node, "type"), textualFlag(node, "required"),
        quoteIfNeeded(node, defaultField), optionalText(node, descriptionField)));
  }

  private JsonNode readOptionsJson(String module, String output) {
    if (output == null || output.isBlank()) {
      throw new ApiException("msfconsole 未输出任何模块选项");
    }
    String clean = output.replaceAll("\\u001B\\[[0-?]*[ -/]*[@-~]", "");
    int start = clean.indexOf('{');
    if (start >= 0) {
      try {
        JsonNode root = objectMapper.readTree(clean.substring(start));
        JsonNode options = root.get("options");
        if (options != null && (options.isObject() || options.isArray())) {
          return options;
        }
        if (options == null && root.isObject() && !root.isEmpty()
            && java.util.stream.StreamSupport.stream(root.spliterator(), false)
                .allMatch(value -> value.isObject() && value.has("required"))) return root;
      } catch (Exception ignore) {
        log.debug("MSF 模块 {} 选项 JSON 解析失败", module);
      }
    }
    throw new ApiException("无法解析模块 " + module + " 的选项信息（msf 版本可能不兼容）");
  }

  private String optionalText(JsonNode node, String field) {
    JsonNode value = node.get(field);
    if (value == null || value.isNull()) return null;
    return value.asText(null);
  }

  private boolean textualFlag(JsonNode node, String field) {
    JsonNode value = node == null ? null : node.get(field);
    if (value == null || value.isNull()) return false;
    if (value.isBoolean()) return value.asBoolean();
    String s = value.asText("").trim().toLowerCase(Locale.ROOT);
    return "true".equals(s) || "yes".equals(s);
  }

  private String quoteIfNeeded(JsonNode node, String field) {
    JsonNode value = node == null ? null : node.get(field);
    if (value == null || value.isNull()) return "";
    if (value.isValueNode()) return value.asText();
    return value.toString();
  }

  private static String abbrev(String value, int max) {
    String clean = value == null ? "" : value.replaceAll("\\s+", " ").trim();
    return clean.length() <= max ? clean : clean.substring(0, max - 1) + "…";
  }

  private String waitFor(Process process, String module) throws ApiException {
    ExecutorService reader = Executors.newSingleThreadExecutor();
    Future<String> output = reader.submit(() -> readLimited(process.getInputStream()));
    try {
      long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(timeoutSeconds);
      while (!process.waitFor(250, TimeUnit.MILLISECONDS)) {
        if (System.nanoTime() >= deadline) {
          process.destroyForcibly();
          process.waitFor(5, TimeUnit.SECONDS);
          throw new ApiException("读取 MSF 模块 " + module + " 选项超时（>" + timeoutSeconds + "s）");
        }
      }
      return output.get(10, TimeUnit.SECONDS);
    } catch (ApiException ex) {
      throw ex;
    } catch (Exception ex) {
      throw new ApiException("读取 MSF 模块选项失败：" + abbrev(ex.getMessage(), 120));
    } finally {
      reader.shutdownNow();
    }
  }

  private String readLimited(InputStream input) throws Exception {
    try (input) {
      byte[] data = input.readNBytes(MAX_OUTPUT_BYTES + 1);
      if (data.length > MAX_OUTPUT_BYTES) {
        throw new ApiException("MSF 模块选项输出超过安全大小限制");
      }
      return new String(data, StandardCharsets.UTF_8);
    }
  }

  /** 单个模块选项描述。 */
  public record ModuleOption(
      String name, String type, boolean required, String defaultValue, String description) {}

  /** Round 311：缓存条目。 */
  private record CachedOptions(List<ModuleOption> options, long cachedAtMillis) {}
}

