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
 * <p>通过 {@code msfconsole -Q -x "use &lt;module&gt;; options -j; exit"} 拉取 JSON。RHOST/RHOSTS/
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

  public MsfModuleOptionService(
      ExecutableLocator locator,
      ObjectMapper objectMapper,
      @Value("${toolbox.execution.msf-path:msfconsole}") String configuredExecutable,
      @Value("${toolbox.execution.msf-timeout-seconds:600}") long timeoutSeconds) {
    this.locator = locator;
    this.objectMapper = objectMapper;
    this.configuredExecutable = configuredExecutable;
    this.timeoutSeconds = timeoutSeconds;
  }

  /** 返回某模块的可配置选项（不含服务端保留键）。 */
  public List<ModuleOption> options(String modulePath) {
    String module = normalizeModule(modulePath);
    Path executable = requireExecutable();
    String script = "use " + module + "; options -j; exit";
    ProcessBuilder builder =
        ProcessEnvironmentSanitizer.sanitize(
            new ProcessBuilder(executable.toString(), "-Q", "-x", script));
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

  private List<ModuleOption> parse(String module, String output) {
    JsonNode options = readOptionsJson(module, output);
    List<ModuleOption> result = new ArrayList<>();
    if (options == null || !options.isObject()) {
      return result;
    }
    Iterator<Map.Entry<String, JsonNode>> it = options.fields();
    while (it.hasNext()) {
      Map.Entry<String, JsonNode> field = it.next();
      String name = field.getKey().trim();
      if (name.isEmpty() || RESERVED_OPTION_KEYS.contains(name.toUpperCase(Locale.ROOT))) {
        continue;
      }
      JsonNode node = field.getValue();
      String type = optionalText(node, "type");
      boolean required = textualFlag(node, "required");
      String def = quoteIfNeeded(node, "default");
      String desc = optionalText(node, "desc");
      result.add(new ModuleOption(name, type, required, def, desc));
    }
    result.sort(
        (a, b) -> {
          if (a.required() != b.required()) return a.required() ? -1 : 1;
          return a.name().compareToIgnoreCase(b.name());
        });
    return result;
  }

  private JsonNode readOptionsJson(String module, String output) {
    if (output == null || output.isBlank()) {
      throw new ApiException("msfconsole 未输出任何模块选项");
    }
    int start = output.indexOf('{');
    if (start >= 0) {
      try {
        JsonNode root = objectMapper.readTree(output.substring(start));
        JsonNode options = root.get("options");
        if (options != null && options.isObject()) {
          return options;
        }
        return root;
      } catch (Exception ignore) {
        log.debug("MSF 模块 {} 选项 JSON 解析失败，回退文本解析", module);
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
}