package com.bachelor.toolbox.msf;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.tool.FindingDraft;
import com.bachelor.toolbox.tool.MsfScanTool;
import com.bachelor.toolbox.tool.ToolExecutionObserver;
import com.bachelor.toolbox.tool.ToolExecutionResult;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.TargetPolicyService;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import org.springframework.stereotype.Component;

/**
 * 对同一授权目标逐个执行所选 Metasploit 模块，并按模块/主机聚合、去重、限流，产出
 * {@link ToolExecutionResult}。
 *
 * <p>Metasploit 未提供像 Nuclei {@code -t} 那样的批量模板参数，必须以 {@code -x <script>}
 * 为每个模块启动一次 msfconsole。本引擎在 Java 侧遍历多个模块并复用 {@link MsfScanTool}
 * 的单一模块执行（含安全校验与命中的授权范围过滤），从而提供「多模块遍历」语义。
 */
@Component
public class MsfScanEngine {
  private static final int MAX_MODULES = 25;
  private final MsfScanTool tool;
  private final TargetPolicyService policy;

  public MsfScanEngine(MsfScanTool tool, TargetPolicyService policy) {
    this.tool = tool;
    this.policy = policy;
  }

  /** 批量执行已选定的模块。调用方已保证 {@code modules} 内的路径合法且属于 auxiliary/exploit。 */
  public ToolExecutionResult runMany(
      AuthorizedTarget target,
      List<String> modules,
      Map<String, Object> options,
      ToolExecutionObserver observer) {
    String host = policy.validatedHost(target);
    List<String> normalized = normalize(modules);
    List<ModuleRun> runs = new ArrayList<>();
    List<FindingDraft> aggregated = new ArrayList<>();
    Map<String, Object> perModule = new LinkedHashMap<>();
    int totalMatches = 0;

    for (int i = 0; i < normalized.size(); i++) {
      String module = normalized.get(i);
      if (observer.isCancellationRequested()) {
        throw new ApiException("任务已取消");
      }
      observer.heartbeat("Metasploit 批量执行：" + (i + 1) + "/" + normalized.size() + " " + module);
      ToolExecutionResult result;
      try {
        result = tool.execute(target, params(module, options), observer);
      } catch (Exception ex) {
        perModule.put(module, Map.of("module", module, "error", abbreviate(ex.getMessage(), 200)));
        runs.add(new ModuleRun(module, 0, true));
        continue;
      }
      int matches = matchCount(result);
      totalMatches += matches;
      aggregated.addAll(result.findings());
      perModule.put(module, Map.of("module", module, "matchCount", matches, "status", "OK"));
      runs.add(new ModuleRun(module, matches, false));
    }

    int before = aggregated.size();
    List<FindingDraft> deduped = deduplicate(aggregated);
    runs.sort(Comparator.comparing(ModuleRun::module));
    Map<String, Object> data = new LinkedHashMap<>();
    data.put("host", host);
    data.put("modules", perModule);
    data.put("matchCount", totalMatches);
    data.put("deduplicated", before - deduped.size());
    data.put("dependencyPresent", true);
    data.put("moduleRuns", runs.stream().map(ModuleRun::asMap).toList());
    return new ToolExecutionResult(
        "Metasploit 模块批量执行完成，命中 " + deduped.size() + " 项",
        data,
        List.copyOf(deduped));
  }

  private Map<String, Object> params(String module, Map<String, Object> options) {
    Map<String, Object> parameters = new HashMap<>();
    parameters.put("module", module);
    if (options != null && !options.isEmpty()) {
      parameters.put("options", Map.copyOf(options));
    }
    return parameters;
  }

  private List<String> normalize(List<String> modules) {
    if (modules == null || modules.isEmpty()) {
      throw new ApiException("请至少选择一个 Metasploit 模块");
    }
    if (modules.size() > MAX_MODULES) {
      throw new ApiException("单次 MSF 批量执行最多选择 " + MAX_MODULES + " 个模块");
    }
    List<String> result = new ArrayList<>();
    Set<String> seen = new LinkedHashSet<>();
    for (String raw : modules) {
      String module = String.valueOf(raw).trim().toLowerCase(Locale.ROOT);
      if (module.isBlank() || module.length() > 256) {
        throw new ApiException("MSF 模块路径不合法");
      }
      if (!(module.startsWith("auxiliary/") || module.startsWith("exploit/"))) {
        throw new ApiException("仅允许 auxiliary 或 exploit 模块在授权范围内执行");
      }
      if (module.matches(".*(\\s|[;&|>`$'\"]).*")
          || module.contains("..")
          || module.contains("\\")) {
        throw new ApiException("模块路径不合法");
      }
      if (!seen.add(module)) {
        throw new ApiException("MSF 模块不能重复选择");
      }
      result.add(module);
    }
    return result;
  }

  private int matchCount(ToolExecutionResult result) {
    Object match = result.data() == null ? null : result.data().get("matchCount");
    if (match instanceof Number number) return number.intValue();
    return result.findings() == null ? 0 : result.findings().size();
  }

  /** 按漏洞码去重，保留最严重的一条（不同模块可能对同一主机产生同码命中）。 */
  private List<FindingDraft> deduplicate(List<FindingDraft> findings) {
    Map<String, FindingDraft> byKey = new LinkedHashMap<>();
    List<String> order = new ArrayList<>();
    for (FindingDraft finding : findings) {
      String key = keyFor(finding);
      if (!byKey.containsKey(key)) {
        order.add(key);
        byKey.put(key, finding);
      } else if (severityRank(finding.severity()) > severityRank(byKey.get(key).severity())) {
        byKey.put(key, finding);
      }
    }
    List<FindingDraft> deduped = new ArrayList<>();
    for (String key : order) deduped.add(byKey.get(key));
    return deduped;
  }

  private String keyFor(FindingDraft finding) {
    return finding.vulnerabilityCode() != null && !finding.vulnerabilityCode().isBlank()
        ? finding.vulnerabilityCode()
        : String.valueOf(finding.title());
  }

  private int severityRank(String severity) {
    return switch (String.valueOf(severity).toUpperCase(Locale.ROOT)) {
      case "CRITICAL" -> 5;
      case "HIGH" -> 4;
      case "MEDIUM" -> 3;
      case "LOW" -> 2;
      default -> 1;
    };
  }

  private String abbreviate(String value, int max) {
    String clean = value == null ? "" : value.replaceAll("\\s+", " ").trim();
    return clean.length() <= max ? clean : clean.substring(0, max) + "…";
  }

  private record ModuleRun(String module, int matches, boolean failed) {
    Map<String, Object> asMap() {
      return Map.of("module", module, "matchCount", matches);
    }
  }
}