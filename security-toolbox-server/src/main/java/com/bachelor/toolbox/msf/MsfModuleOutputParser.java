package com.bachelor.toolbox.msf;

import com.bachelor.toolbox.common.ApiException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;
import org.springframework.stereotype.Component;

/**
 * 解析 {@code msfconsole} 枚举脚本输出的模块列表。
 *
 * <p>枚举脚本对被加载的每个 auxiliary/exploit 模块输出一行、以 {@code \t} 分隔的：
 * {@code <category>\t<modulePath>\t<name>\t<rank>\t<description>}。这里只对列进行强校验与归一化，
 * 对 name/description 的语义不做过强假设，从而对框架版本差异保持稳健。
 */
@Component
public class MsfModuleOutputParser {
  private static final Pattern TAB = Pattern.compile("\t");
  private static final Set<String> SUPPORTED_CATEGORIES =
      Set.of("auxiliary", "exploit");
  private static final int MAX_MODULE_PATH = 256;
  private static final Set<String> ACCEPTABLE_RANKS =
      Set.of(
          "manual", "low", "normal", "average", "good", "great", "excellent");

  public List<MsfLine> parse(String output) {
    if (output == null || output.isBlank()) {
      return List.of();
    }
    List<MsfLine> result = new ArrayList<>();
    for (String raw : output.split("\\R")) {
      String line = raw.strip();
      if (line.isEmpty()) {
        continue;
      }
      MsfLine item = tryParse(line);
      if (item != null) {
        result.add(item);
      }
    }
    return result;
  }

  MsfLine tryParse(String line) {
    String[] parts = TAB.split(line, -1);
    if (parts.length < 3) {
      return null;
    }
    String category = String.valueOf(parts[0]).trim().toLowerCase(Locale.ROOT);
    if (!SUPPORTED_CATEGORIES.contains(category)) {
      return null;
    }
    String modulePath = parts[1].trim().toLowerCase(Locale.ROOT);
    if (modulePath.isEmpty()
        || modulePath.length() > MAX_MODULE_PATH
        || !modulePath.startsWith(category + "/")
        || modulePath.contains("..")
        || modulePath.contains("\\")
        || modulePath.matches(".*(\\s|[;&|>`$'\"]).*")) {
      throw new ApiException("Metasploit 模块枚举输出包含非法模块路径");
    }
    String name = sanitize(parts[2]);
    if (name.isEmpty() || name.length() > 200) {
      name = abbreviate(modulePath, 200);
    }
    String rank = "normal";
    if (parts.length >= 4) {
      String candidate = String.valueOf(parts[3]).trim().toLowerCase(Locale.ROOT);
      if (!candidate.isEmpty()) {
        rank = ACCEPTABLE_RANKS.contains(candidate) ? candidate : "manual";
      }
    }
    String description = parts.length >= 5 ? sanitize(parts[4]) : "";
    return new MsfLine(category, modulePath, name, rank, description);
  }

  private String sanitize(String value) {
    if (value == null) {
      return "";
    }
    String clean = value.strip();
    clean = clean.replaceAll("\\p{Cntrl}", " ");
    clean = clean.replaceAll("\\s{2,}", " ").trim();
    if (clean.length() > 1000) {
      clean = clean.substring(0, 999) + "…";
    }
    return clean;
  }

  private String abbreviate(String value, int max) {
    String clean = value == null ? "" : value.strip();
    return clean.length() <= max ? clean : clean.substring(0, max - 1) + "…";
  }

  public record MsfLine(String category, String modulePath, String name, String rank, String description) {}
}