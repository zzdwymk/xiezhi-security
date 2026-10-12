package com.bachelor.toolbox.ai.capability.core;

import com.bachelor.toolbox.ai.capability.CapabilityKind;
import com.bachelor.toolbox.ai.capability.RiskLevel;
import com.bachelor.toolbox.audit.AuditLog;
import com.bachelor.toolbox.audit.AuditLogRepository;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Component;

/**
 * {@code query_audit} —— 查询平台审计日志（设计文档 §4.2 路线 A）。
 *
 * <p>封装 {@code GET /api/audits}（{@link AuditLogRepository#findByProjectId} /
 * {@link AuditLogRepository#findAllByOrderByCreatedAtDesc}）。
 *
 * <h2>目标绑定：{@link BindingMode#NONE} —— 这里要写清楚"为什么不是 RESOLVED"</h2>
 *
 * <p>审计日志里<strong>含有</strong> {@code resourceId}、{@code relatedTaskId} 等字段，间接可以指向某个目标。但本能力：
 *
 * <ul>
 *   <li>是纯读操作，不产生任何外部影响；
 *   <li>按<strong>项目</strong>维度或全局检索，不以目标为主键——{@code projectId} 过滤走的是
 *       {@link AuditLogRepository#findByProjectId} 的既有语义（项目授权由平台既有机制承担）；
 *   <li>不向任何目标发包。
 * </ul>
 *
 * <p>因此它落在三态语义的第一态"确实不触及任何授权目标"。护栏的 {@code TargetBindingProbe} 会读到
 * {@code BindingMode.NONE} 的<strong>显式声明</strong>才允许跳过 L-A——注意是"显式声明"，不是"解析不到目标"。
 *
 * <h2>为什么审计查询必须是 L1 且无需确认</h2>
 *
 * <p>审计是 Agent 自我核查与事后追责的依据（§6.8"执行账本"）。若把它做成需确认的能力，会形成"想查自己做了什么 →
 * 要先惊动用户 → 用户嫌烦 → 关掉审计能力"的退化路径。读自己的操作记录应当零摩擦。
 */
@Component
public class QueryAuditCapability extends AbstractCoreCapability {

  /** 能力码。 */
  public static final String CODE = "query_audit";

  /** 单次返回上限（与 {@code AuditController} 的 500 上限对齐，这里再收窄到 200）。 */
  private static final int MAX_RESULTS = 200;

  private final AuditLogRepository audits;

  public QueryAuditCapability(AuditLogRepository audits) {
    super(
        CODE,
        "查询审计日志",
        "查询平台的操作审计日志：动作、资源类型与 ID、操作者、结果、时间与详情。"
            + "参数均为可选：projectId（只查该项目相关审计）、action（动作关键字）、"
            + "resourceType（资源类型，如 TASK、FINDING、PROJECT）、limit（条数上限，默认 50，最大 200）。"
            + "只读查询，不向任何授权目标发起动作。",
        CapabilityKind.READ,
        RiskLevel.SAFE,
        false,
        BindingMode.NONE,
        AiCapabilityLayer.L1);
    this.audits = audits;
  }

  @Override
  public Map<String, Object> parameterSchema() {
    Map<String, Object> properties = new LinkedHashMap<>();
    properties.put("projectId", integerProperty(1, "可选：只返回该项目相关的审计记录"));
    properties.put("action", property("string", "可选：动作关键字，如 CREATE_TASK、AGENT_CAPABILITY_DENIED"));
    properties.put("resourceType", property("string", "可选：资源类型，如 TASK、FINDING、PROJECT"));
    properties.put("limit", integerProperty(1, "可选：返回条数上限，默认 50，最大 " + MAX_RESULTS));
    return objectSchema(properties, List.of());
  }

  /** 查询审计日志。 */
  public List<AuditLog> list(Long projectId, String action, String resourceType, Integer limit) {
    int bounded = Math.min(Math.max(limit == null ? 50 : limit, 1), MAX_RESULTS);
    PageRequest page = PageRequest.of(0, bounded);
    List<AuditLog> source =
        projectId != null && projectId > 0
            ? audits.findByProjectId(projectId, projectId.toString(), page).getContent()
            : audits.findAllByOrderByCreatedAtDesc(page).getContent();
    String actionFilter = action == null ? "" : action.trim().toUpperCase(Locale.ROOT);
    String typeFilter = resourceType == null ? "" : resourceType.trim().toUpperCase(Locale.ROOT);
    return source.stream()
        .filter(
            log ->
                actionFilter.isEmpty()
                    || String.valueOf(log.getAction()).toUpperCase(Locale.ROOT).contains(actionFilter))
        .filter(
            log ->
                typeFilter.isEmpty()
                    || typeFilter.equalsIgnoreCase(String.valueOf(log.getResourceType())))
        .toList();
  }
}
