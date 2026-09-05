package com.bachelor.toolbox.msf;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.dependency.ExecutableLocator;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * 直接扫描本机 Metasploit Framework 模块目录来枚举模块元数据，替代依赖 msfconsole 交互控制台
 * 的 Ruby 脚本方案（msfconsole -x 只接受控制台命令，无法执行 {@code framework.modules.each} 式脚本）。
 *
 * <p>模块文件位于 {@code <install>/embedded/framework/modules/<category>/<...>/<sub>.rb}，例如
 * {@code auxiliary/scanner/ssh/ssh_login.rb} 或 {@code exploits/multi/http/web_delivery.rb}。
 * 本枚举器只关注 {@code auxiliary/} 与 {@code exploits/}（磁盘上 exploitations 用复数目录，对应 MSF
 * 语义下的 exploit 模块），其余 encoders/evasion/nops/payloads/post 等类型的文件不纳入漏洞知识库，
 * 与既有仅导入 auxiliary、exploit 的收集口径保持一致。
 */
@Component
public class MsfModuleEnumerator {

  private static final List<String> IMPORTED_TOP_CATEGORIES = List.of("auxiliary", "exploits");
  private static final int MAX_MODULES = 200_000;
  private static final int MAX_MODULE_SOURCE_BYTES = 32 * 1024;
  private static final Set<String> ACCEPTABLE_RANKS =
      Set.of("manual", "low", "normal", "average", "good", "great", "excellent");
  private static final String FALLBACK_DESCRIPTION = "Metasploit 模块官方未提供描述。";

  private final ExecutableLocator locator;
  private final List<String> executableCandidates;

  public MsfModuleEnumerator(
      ExecutableLocator locator,
      @Value("${toolbox.execution.msf-path:msfconsole}") String configuredExecutable) {
    this.locator = locator;
    Set<String> candidates = new LinkedHashSet<>();
    if (configuredExecutable != null && !configuredExecutable.isBlank()) {
      candidates.add(configuredExecutable.trim());
    }
    candidates.add("msfconsole");
    candidates.add("msfconsole.bat");
    this.executableCandidates = List.copyOf(candidates);
  }

  /** 扫描并返回本机 auxiliary/exploit 模块元数据（按模块路径排序）。 */
  public List<MsfModuleOutputParser.MsfLine> enumerate() {
    Path modulesRoot = resolveModulesRoot();
    List<MsfModuleOutputParser.MsfLine> result = new ArrayList<>();
    int remaining = MAX_MODULES;
    for (String top : IMPORTED_TOP_CATEGORIES) {
      Path categoryRoot = modulesRoot.resolve(top);
      if (!Files.isDirectory(categoryRoot)) continue;
      try (Stream<Path> walk = Files.walk(categoryRoot)) {
        for (Path file : walk.toList()) {
          if (remaining <= 0) throw new ApiException("MSF 模块数量超过安全上限 " + MAX_MODULES);
          if (!isModuleFile(file)) continue;
          MsfModuleOutputParser.MsfLine line = toLine(top, modulesRoot, file);
          if (line != null) {
            result.add(line);
            remaining--;
          }
        }
      } catch (IOException ex) {
        throw new ApiException("MSF 模块目录扫描失败：" + ex.getMessage());
      }
    }
    result.sort(Comparator.comparing(MsfModuleOutputParser.MsfLine::modulePath));
    return result;
  }

  private Path resolveModulesRoot() {
    Path executable;
    try {
      executable = locator.find(executableCandidates).orElse(null);
    } catch (RuntimeException ex) {
      throw new ApiException("未检测到 MetasploitFramework，无法同步 MSF 模块库");
    }
    if (executable == null) {
      throw new ApiException("未检测到 MetasploitFramework，无法同步 MSF 模块库");
    }
    Path executableDir = executable.toAbsolutePath().normalize().getParent();
    Path installRoot = executableDir;
    if (executableDir != null
        && executableDir.getFileName() != null
        && "bin".equalsIgnoreCase(executableDir.getFileName().toString())) {
      installRoot = executableDir.getParent();
    }
    if (installRoot == null) {
      throw new ApiException("未检测到 MetasploitFramework，无法同步 MSF 模块库");
    }
    Path modulesRoot = installRoot.resolve("embedded").resolve("framework").resolve("modules");
    for (String top : IMPORTED_TOP_CATEGORIES) {
      if (Files.isDirectory(modulesRoot.resolve(top))) {
        return modulesRoot;
      }
    }
    throw new ApiException("未检测到 MetasploitFramework，无法同步 MSF 模块库");
  }

  private boolean isModuleFile(Path file) {
    if (!Files.isRegularFile(file)) return false;
    return file.getFileName() != null
        && file.getFileName().toString().toLowerCase(Locale.ROOT).endsWith(".rb");
  }

  private MsfModuleOutputParser.MsfLine toLine(String top, Path modulesRoot, Path file) {
    String relative = modulesRoot.relativize(file).toString().replace('\\', '/');
    if (relative.endsWith(".rb")) relative = relative.substring(0, relative.length() - 3);
    String modulePath = normalizeModulePath(top, relative);
    if (modulePath == null) return null;
    if (!modulePath.matches("(auxiliary|exploit)/.*")
        || modulePath.contains("..")
        || modulePath.matches(".*([\\s;&|>`$'\"]).*")) {
      return null;
    }
    ModuleMeta meta = extractMeta(file);
    String category = "exploits".equals(top) ? "exploit" : "auxiliary";
    return new MsfModuleOutputParser.MsfLine(
        category, modulePath, meta.name, meta.rank, meta.description);
  }

  /** 将顶层复数目录改回语义单数，组成 auxiliary/... 或 exploit/... 的模块全路径。 */
  private String normalizeModulePath(String top, String relative) {
    String prefix = top + "/";
    String rest = relative.startsWith(prefix) ? relative.substring(prefix.length()) : relative;
    if (rest.isEmpty()) return null;
    String category = "exploits".equals(top) ? "exploit" : "auxiliary";
    return category + "/" + rest;
  }

  private ModuleMeta extractMeta(Path file) {
    String body = readBounded(file);
    String name = extractQuoted(body, "name");
    String description = extractQuoted(body, "description");
    String rank = extractRank(body);
    return new ModuleMeta(
        name.isBlank() ? "" : name,
        description.isBlank() ? FALLBACK_DESCRIPTION : description,
        rank);
  }

  private String readBounded(Path file) {
    try {
      if (Files.size(file) > MAX_MODULE_SOURCE_BYTES) {
        try (InputStream in = Files.newInputStream(file)) {
          byte[] data = in.readNBytes(MAX_MODULE_SOURCE_BYTES);
          return new String(data, StandardCharsets.UTF_8);
        }
      }
      return Files.readString(file, StandardCharsets.UTF_8);
    } catch (IOException ex) {
      return "";
    }
  }

  private String extractQuoted(String body, String key) {
    if (body == null || body.isBlank()) return "";
    String pattern = "(?i)['\"]" + key + "['\"]\\s*=>\\s*['\"]([^'\"]{1,1950})['\"]";
    Matcher matcher = Pattern.compile(pattern).matcher(body);
    if (matcher.find()) {
      return matcher.group(1).replaceAll("\\s+", " ").trim();
    }
    // 多数 MSF 模块用 %q{...} 承载多行描述，捕获其首段作为描述。
    if ("description".equalsIgnoreCase(key)) {
      String block =
          "(?i)['\"]description['\"]\\s*=>\\s*%q\\{[^\\}]{1,1950}";
      Matcher blockMatcher = Pattern.compile(block, Pattern.DOTALL).matcher(body);
      if (blockMatcher.find()) {
        String value = blockMatcher.group().substring(blockMatcher.group().lastIndexOf('{') + 1);
        return value.replaceAll("\\s+", " ").trim();
      }
    }
    return "";
  }

  private String extractRank(String body) {
    if (body == null || body.isBlank()) return "normal";
    Matcher matcher =
        Pattern.compile("(?i)['\"]Rank['\"]\\s*=>\\s*['\"]?([A-Za-z]+)['\"]?").matcher(body);
    if (matcher.find()) {
      String rank = matcher.group(1).toLowerCase(Locale.ROOT);
      return ACCEPTABLE_RANKS.contains(rank) ? rank : "normal";
    }
    Matcher constant = Pattern.compile("(?i)Rank\\s*=\\s*(Manual|Low|Normal|Average|Good|Great|Excellent)\\s*Ranking").matcher(body);
    if (constant.find()) {
      String rank = constant.group(1).toLowerCase(Locale.ROOT);
      return ACCEPTABLE_RANKS.contains(rank) ? rank : "normal";
    }
    return "normal";
  }

  private record ModuleMeta(String name, String description, String rank) {}
}