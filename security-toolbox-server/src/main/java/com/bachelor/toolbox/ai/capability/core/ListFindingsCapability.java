package com.bachelor.toolbox.ai.capability.core;

import com.bachelor.toolbox.ai.capability.CapabilityKind;
import com.bachelor.toolbox.ai.capability.RiskLevel;
import com.bachelor.toolbox.finding.Finding;
import com.bachelor.toolbox.finding.FindingRepository;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.springframework.stereotype.Component;

/**
 * {@code list_findings} —— 列出漏洞发现记录（设计文档 §4.2 路线 A）。
 *
 * <p>封装 {@code GET /api/findings} 的查询语义。
 *
 * <h2>目标绑定：{@link BindingMode#NONE}</h2>
 *
 * <p>按项目/目标/等级/状态检索<strong>已经存在的</strong>发现记录，只读、无副作用、不向任何目标发起动作。
 * 可选参数 {@code targetId} 只是过滤条件——它<strong>不</strong>把本能力变成"触及目标"的能力，也<strong>不</strong>因为
 * "有时带 targetId"而改变绑定模式。
 *
 * <p>为什么必须显式声明为 {@code NONE} 而不是"反正解析不到就返回空集"：护栏
 * （{@code TargetBindingProbe.emptyBindingAllowed}）只承认<strong>显式声明</strong>的空集。一个漏声明的只读能力会被
 * 护栏以 {@code MISSING_TARGET_BINDING} 拒绝——这是刻意的 fail-closed：宁可误拦一个只读能力，也不能让一个漏声明的
 * 扫描能力静默跳过 L-A（§10 失败模式表）。
 */
@Component
public class ListFindingsCapability extends AbstractCoreCapability {

  /** 能力码。 */
  public static final String CODE = "list_findings";

  /** 单次返回上限，防止把整库发现灌进上下文。 */
  private static final int MAX_RESULTS = 200;

  private static final List<String> SEVERITIES =
      List.of("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO");

  private final FindingRepository findings;

  public ListFindingsCapability(FindingRepository findings) {
    super(
        CODE,
        "列出漏洞发现",
        "列出平台的漏洞发现记录，可按项目、目标、等级、状态、关键字过滤。"
            + "参数均为可选过滤条件：projectId、targetId、severity（CRITICAL/HIGH/MEDIUM/LOW/INFO）、"
            + "status（OPEN/CONFIRMED/FALSE_POSITIVE/FIXED）、query（标题关键字）、limit。"
            + "只读查询，不向任何授权目标发起动作。",
        CapabilityKind.READ,
        RiskLevel.SAFE,
        false,
        BindingMode.NONE,
        AiCapabilityLayer.L1);
    this.findings = findings;
  }

  @Override
  public Map<String, Object> parameterSchema() {
    Map<String, Object> properties = new LinkedHashMap<>();
    properties.put("projectId", integerProperty(1, "可选：项目 ID 过滤"));
    properties.put("targetId", integerProperty(1, "可选：目标 ID 过滤（过滤条件，不是授权校验依据）"));
    properties.put("severity", enumProperty(SEVERITIES, "可选：漏洞等级过滤"));
    properties.put("status", property("string", "可选：处置状态过滤（OPEN/CONFIRMED/FALSE_POSITIVE/FIXED）"));
    properties.put("query", property("string", "可选：标题关键字"));
    properties.put("limit", integerProperty(1, "可选：返回条数上限，默认 50，最大 " + MAX_RESULTS));
    return objectSchema(properties, List.of());
  }

  /** 查询发现记录。 */
  public List<Finding> list(
      Long projectId, Long targetId, String severity, String status, String query, Integer limit) {
    int bounded = Math.min(Math.max(limit == null ? 50 : limit, 1), MAX_RESULTS);
    String keyword = query == null ? "" : query.trim().toLowerCase(Locale.ROOT);
    String severityFilter = severity == null ? null : severity.trim().toUpperCase(Locale.ROOT);
    String statusFilter = status == null ? null : status.trim().toUpperCase(Locale.ROOT);
    return findings.findAllByOrderByCreatedAtDesc().stream()
        .filter(finding -> targetId == null || targetId.equals(finding.getTargetId()))
        .filter(
            finding ->
                severityFilter == null
                    || severityFilter.equalsIgnoreCase(String.valueOf(finding.getSeverity())))
        .filter(
            finding ->
                statusFilter == null
                    || statusFilter.equalsIgnoreCase(String.valueOf(finding.getStatus())))
        .filter(
            finding ->
                keyword.isEmpty()
                    || String.valueOf(finding.getTitle()).toLowerCase(Locale.ROOT).contains(keyword))
        .sorted(Comparator.comparing(Finding::getCreatedAt, Comparator.nullsLast(Comparator.reverseOrder())))
        .limit(bounded)
        .toList();
  }
}
