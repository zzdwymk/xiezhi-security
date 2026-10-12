package com.bachelor.toolbox.ai.endpoint;

import com.bachelor.toolbox.ai.capability.CapabilityKind;
import com.bachelor.toolbox.ai.capability.RiskLevel;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;

/**
 * 端点风险自动推断（设计文档 §4.2 路线 B 的风险推断表）。
 *
 * <h2>推断表</h2>
 *
 * <table border="1">
 *   <caption>信号 → 等级</caption>
 *   <tr><th>信号</th><th>推断等级</th></tr>
 *   <tr><td>{@code GET} / {@code HEAD}</td><td>{@link RiskLevel#SAFE}</td></tr>
 *   <tr><td>{@code POST}（创建类）</td><td>{@link RiskLevel#SENSITIVE}</td></tr>
 *   <tr><td>{@code PUT} / {@code PATCH}（更新类）</td><td>{@link RiskLevel#SENSITIVE}</td></tr>
 *   <tr><td>{@code DELETE}</td><td>{@link RiskLevel#DESTRUCTIVE}</td></tr>
 *   <tr><td>路径含 {@code shutdown} / {@code reset} / {@code cleanup}</td><td>{@link RiskLevel#DESTRUCTIVE}</td></tr>
 *   <tr><td>路径含 {@code execute} / {@code run} / {@code scan}</td><td>{@link RiskLevel#SENSITIVE} + 需确认</td></tr>
 *   <tr><td colspan="2"><b>以下为 X-3 / X-5 扩展（见下节）</b></td></tr>
 *   <tr><td>路径含 {@code start}/{@code stop}/{@code enable}/{@code proxy}/{@code capture}/{@code import}/{@code export}</td>
 *       <td>{@link RiskLevel#SENSITIVE} + 需确认</td></tr>
 *   <tr><td>路径含 {@code grant} / {@code revoke} / {@code assign}</td><td>{@link RiskLevel#DESTRUCTIVE}</td></tr>
 *   <tr><td>只读方法且路径含 {@code audit}/{@code ledger}/{@code log}/{@code setting}/{@code user}/{@code auth}</td>
 *       <td>{@link RiskLevel#SENSITIVE}（{@code BATCH}，不逐次确认）</td></tr>
 *   <tr><td>未知 HTTP 方法</td><td>{@link RiskLevel#DESTRUCTIVE}</td></tr>
 * </table>
 *
 * <h2>三处刻意的强化（保守优先，宁高勿低）</h2>
 *
 * <ol>
 *   <li><b>仅按 HTTP 方法推断会让"间接执行"漏级</b>：{@code POST /api/tasks} 会创建一个真正去扫描目标的异步任务，按方法推断是
 *       {@code SENSITIVE}，但它对授权目标发起了实际执行，按 §6.6 属于 {@code REQUIRED} 逐次确认。因此
 *       {@link #inferRequiresApproval} 对"会落到目标上的 POST"也要求确认。
 *   <li><b>路径关键词匹配的是路径段，不是子串</b>：若用子串匹配，{@code /api/runtime} 里的 {@code run} 会把一个只读端点
 *       误升级为执行类。本类按路径段做整段或 {@code -}/{@code _} 分词匹配。
 *   <li><b>关键词表可枚举、可测试、可人工校准</b>：设计文档 §4.2 要求"推断结果写入配置文件，支持人工校准高危项"。本类只做
 *       推断，<b>不</b>读写配置文件；校准入口是 {@link EndpointCapabilityScanner#setRiskOverrides}。
 * </ol>
 *
 * <h2>超出设计文档表格的两条安全修订（X-3、X-5）</h2>
 *
 * <p>§4.2 的推断表只列了 {@code shutdown}/{@code reset}/{@code cleanup} 与
 * {@code execute}/{@code run}/{@code scan} 六个关键词，只按 HTTP 方法决定其余端点。这两条规则经独立验证者核实存在真实漏洞，
 * 本实现予以修正（如实记录为与设计文档的偏差）：
 *
 * <p><b>X-3：{@code start} 类端点会被推断成 SAFE，但它是高危操作。</b>
 * {@code TrafficProxyService.start()} 完全不做目标/项目授权校验（源码注释明写 "Capture is independent of project and
 * target authorization"）。只认 {@code execute}/{@code run}/{@code scan} 会把
 * {@code POST /api/traffic/proxy/start} 推断成 {@code SAFE} → Agent 零确认启动 MITM 代理并解密记录流量。
 * 因此 {@link #EXECUTION_KEYWORDS} 扩充了服务生命周期（{@code start}/{@code stop}/{@code restart}/{@code enable}/{@code
 * disable}）、流量拦截（{@code proxy}/{@code capture}/{@code mitm}/{@code intercept}）、数据进出
 * （{@code import}/{@code export}/{@code upload}/{@code download}）；{@link #DESTRUCTIVE_KEYWORDS} 扩充了权限变更
 * （{@code grant}/{@code revoke}/{@code assign}/{@code unassign}）。
 *
 * <p><b>X-5：{@code GET} 一律 SAFE 会导致跨项目数据读取。</b>
 * {@code GET /api/audits} 无任何项目归属过滤，按"GET → SAFE"推断即放行 → Agent 可跨项目读取审计日志；同族还有
 * {@code /api/reports/tasks/{taskId}.html}。因此新增 {@link #SENSITIVE_DATA_KEYWORDS}：只读方法命中敏感数据域
 * （{@code audit}/{@code ledger}/{@code log}/{@code setting}/{@code user}/{@code auth}...）时提级为
 * {@code SENSITIVE}。为不与 §6.6 防确认疲劳冲突，这类端点<b>不</b>要求逐次确认，归 {@code BATCH} 批量确认档
 * （见 {@link #isSensitiveDataRead}）。
 *
 * <p><b>与设计文档的第三处偏差</b>：文档表格未说明 {@code DELETE} 之外的高危方法如何处置。本类把 {@code DESTRUCTIVE}
 * 的判定同时纳入路径关键词，即"方法风险"与"路径风险"取<b>较高者</b>，而不是后者覆盖前者。
 */
public final class RiskInference {

  /** 命中即 DESTRUCTIVE 的路径关键词（§4.2）。 */
  private static final Set<String> DESTRUCTIVE_KEYWORDS =
      Set.of(
          "shutdown",
          "reset",
          "cleanup",
          "purge",
          "wipe",
          "destroy",
          // X-3 扩展：权限变更属于影响授权边界的操作（§6.6 REQUIRED），且不可逆。
          "grant",
          "revoke",
          "assign",
          "unassign");

  /** 命中即 SENSITIVE 且需确认的路径关键词（§4.2）。 */
  private static final Set<String> EXECUTION_KEYWORDS =
      Set.of(
          "execute",
          "run",
          "runs",
          "scan",
          "scans",
          "fuzz",
          "attack",
          "exploit",
          "replay",
          "retest",
          // X-3 扩展：服务生命周期与流量拦截类动作。
          // 关键案例：POST /api/traffic/proxy/start 会启动 MITM 代理并解密记录流量，
          // 而 TrafficProxyService.start() 不做目标/项目授权校验（源码注释明写
          // "Capture is independent of project and target authorization"）。
          // 只认 execute/run/scan 会把这条高危端点推断成 SAFE → Agent 零确认启动 MITM。
          "start",
          "stop",
          "restart",
          "enable",
          "disable",
          "proxy",
          "capture",
          "mitm",
          "intercept",
          // X-3 扩展：数据进出（导入/导出/上传）。
          "import",
          "export",
          "upload",
          "download");

  /**
   * X-5：敏感数据域。{@code GET} 命中这些域时不能无条件 SAFE。
   *
   * <p>关键案例：{@code GET /api/audits} 无任何项目归属过滤（{@code AuditController}），按"GET → SAFE"推断即放行，
   * Agent 就能跨项目读取审计日志。同族还有 {@code /api/reports/tasks/{taskId}.html}（无归属校验）。
   *
   * <p>处理方式遵循 §6.6 防确认疲劳：敏感域 GET 提级为 {@link RiskLevel#SENSITIVE}，但<b>不</b>要求逐次确认（归 {@code
   * BATCH}），避免只读查询把确认弹窗刷爆。
   */
  private static final Set<String> SENSITIVE_DATA_KEYWORDS =
      Set.of(
          "audit",
          "audits",
          "ledger",
          "ledgers",
          "log",
          "logs",
          "secret",
          "secrets",
          "credential",
          "credentials",
          "token",
          "tokens",
          "key",
          "keys",
          "setting",
          "settings",
          "config",
          "configs",
          "user",
          "users",
          "auth",
          "permission",
          "permissions",
          "role",
          "roles");

  /** 关键词表以外的"按方法判定为 DESTRUCTIVE"的方法。 */
  private static final Set<String> DESTRUCTIVE_METHODS = Set.of("DELETE");

  /**
   * 需要人工确认的写方法之外的"间接执行"路径关键词。
   *
   * <p>{@code /api/tasks}、{@code /api/workflow-runs}、{@code /api/active-scans} 这类端点用 POST 创建对象，但对象本身
   * 会去执行扫描——属于 §6.6 的 {@code REQUIRED}。
   */
  private static final Set<String> INDIRECT_EXECUTION_KEYWORDS =
      Set.of("task", "tasks", "workflow", "workflows", "workflow-run", "workflow-runs", "active-scan", "active-scans", "dispatch", "dispatches");

  private RiskInference() {}

  /**
   * 按 HTTP 方法与路径推断风险等级。
   *
   * <p>判定顺序（先严后宽，命中即返回）：
   *
   * <ol>
   *   <li>路径命中 DESTRUCTIVE 关键词（shutdown/reset/cleanup/grant/revoke…）
   *   <li>{@code DELETE}
   *   <li>路径命中执行类关键词（execute/run/scan/start/stop/proxy/capture/import/export…）
   *   <li>只读方法命中敏感数据域（audit/ledger/log/setting/user/auth…）→ SENSITIVE（X-5）
   *   <li>按方法推断：GET/HEAD → SAFE；POST/PUT/PATCH → SENSITIVE；未知 → DESTRUCTIVE
   * </ol>
   *
   * @param method HTTP 方法，大小写不敏感；{@code null} 视为未知方法
   * @param path 端点路径（模板形式，如 {@code /api/targets/{id}}）
   * @return 推断出的风险等级；未知方法按最保守的 {@link RiskLevel#DESTRUCTIVE} 处理
   */
  public static RiskLevel inferRisk(String method, String path) {
    String normalizedMethod = normalizeMethod(method);
    Set<String> tokens = pathTokens(path);

    if (intersects(tokens, DESTRUCTIVE_KEYWORDS)) {
      return RiskLevel.DESTRUCTIVE;
    }
    if (DESTRUCTIVE_METHODS.contains(normalizedMethod)) {
      return RiskLevel.DESTRUCTIVE;
    }
    if (intersects(tokens, EXECUTION_KEYWORDS)) {
      return RiskLevel.SENSITIVE;
    }
    boolean readOnly = Set.of("GET", "HEAD", "OPTIONS", "TRACE").contains(normalizedMethod);
    if (readOnly && intersects(tokens, SENSITIVE_DATA_KEYWORDS)) {
      // X-5：只读不等于无风险。这些域的数据没有项目归属过滤，跨项目读取即越权。
      return RiskLevel.SENSITIVE;
    }
    return switch (normalizedMethod) {
      case "GET", "HEAD", "OPTIONS", "TRACE" -> RiskLevel.SAFE;
      case "POST", "PUT", "PATCH" -> RiskLevel.SENSITIVE;
      // 未知方法：按 §10 "保守优先（宁高勿低）"，未知一律按不可逆处理，交由人工确认与白名单决定是否放行。
      default -> RiskLevel.DESTRUCTIVE;
    };
  }

  /**
   * 推断能力类别。
   *
   * <p>方法到类别的映射是直白的，但路径关键词可以把它推高：命中执行类关键词的端点属于 {@link CapabilityKind#EXECUTE}
   * （对目标发起实际动作），命中 shutdown/cleanup 的属于 {@link CapabilityKind#ADMIN}。这与 §6.2 "授权校验依据是是否触及目标，
   * 而不是 kind"并不矛盾——{@code kind} 只用于分类与展示，这里只是让分类更贴近语义。
   */
  public static CapabilityKind inferKind(String method, String path) {
    String normalizedMethod = normalizeMethod(method);
    Set<String> tokens = pathTokens(path);
    if (intersects(
            tokens,
            Set.of(
                "shutdown", "cleanup", "reset", "purge", "wipe", "destroy",
                "grant", "revoke", "assign", "unassign"))
        || normalizedMethod.equals("DELETE")) {
      return CapabilityKind.ADMIN;
    }
    if (intersects(tokens, EXECUTION_KEYWORDS) || intersects(tokens, INDIRECT_EXECUTION_KEYWORDS)) {
      return CapabilityKind.EXECUTE;
    }
    return switch (normalizedMethod) {
      case "GET", "HEAD", "OPTIONS", "TRACE" -> CapabilityKind.READ;
      case "POST", "PUT", "PATCH" -> CapabilityKind.WRITE;
      default -> CapabilityKind.ADMIN;
    };
  }

  /**
   * 推断是否需要人工确认。
   *
   * <p>判定顺序（命中任一即需确认）：
   *
   * <ol>
   *   <li>{@link RiskLevel#DESTRUCTIVE} —— 不可逆操作，§6.6 的 {@code REQUIRED}
   *   <li>路径命中执行类关键词（{@code execute}/{@code run}/{@code scan}...）—— 对目标发起实际执行
   *   <li>写方法且路径命中间接执行关键词（{@code /api/tasks}、{@code /api/workflow-runs}...）—— 创建的对象会去扫描目标
   *   <li>写方法且路径含目标参数（{@code {targetId}}）—— 直接作用于授权目标
   * </ol>
   *
   * <p><b>敏感数据域的只读端点（X-5）刻意不在此列</b>：它们被提级为 {@link RiskLevel#SENSITIVE}，但归 {@code BATCH}
   * 批量确认而非 {@code REQUIRED} 逐次确认。§6.6 的防确认疲劳要求 {@code REQUIRED} 只覆盖真正高危的少数操作；若把
   * {@code GET /api/audits}、{@code GET /api/settings} 这类常规查询也做成逐次确认，用户会迅速麻木，反而削弱护栏。
   * 需要判断这类端点时用 {@link #isSensitiveDataRead}。
   *
   * <p>其余归 {@code BATCH}/{@code NONE}，不弹逐次确认。
   */
  public static boolean inferRequiresApproval(String method, String path) {
    RiskLevel risk = inferRisk(method, path);
    if (risk == RiskLevel.DESTRUCTIVE) {
      return true;
    }
    Set<String> tokens = pathTokens(path);
    if (intersects(tokens, EXECUTION_KEYWORDS)) {
      return true;
    }
    String normalizedMethod = normalizeMethod(method);
    boolean mutating = Set.of("POST", "PUT", "PATCH", "DELETE").contains(normalizedMethod);
    if (!mutating) {
      return false;
    }
    if (intersects(tokens, INDIRECT_EXECUTION_KEYWORDS)) {
      return true;
    }
    return touchesTargetParameter(path);
  }

  /** 该端点是否属于 §6.4 白名单（需显式开启才能调用）。 */
  public static boolean isWhitelisted(String method, String path) {
    return inferRisk(method, path) == RiskLevel.DESTRUCTIVE
        || inferKind(method, path) == CapabilityKind.ADMIN;
  }

  /**
   * 该端点是否只读却触及敏感数据域（X-5）。
   *
   * <p>供治理层把这类端点归入 {@code BATCH} 批量确认档，而不是当成无副作用的 {@code NONE} 自动放行。
   * {@code GET /api/audits} 无项目归属过滤，跨项目读取审计日志即越权，因此不能按"GET 一定安全"处理。
   */
  public static boolean isSensitiveDataRead(String method, String path) {
    String normalizedMethod = normalizeMethod(method);
    if (!Set.of("GET", "HEAD", "OPTIONS", "TRACE").contains(normalizedMethod)) {
      return false;
    }
    return intersects(pathTokens(path), SENSITIVE_DATA_KEYWORDS);
  }

  /** 敏感数据域关键词快照（只读），供护栏与提示词构建复用。 */
  public static Set<String> sensitiveDataKeywords() {
    return SENSITIVE_DATA_KEYWORDS;
  }

  /** 执行类关键词快照（只读），供护栏与提示词构建复用。 */
  public static Set<String> executionKeywords() {
    return EXECUTION_KEYWORDS;
  }

  // ---------------------------------------------------------------- 内部实现

  /** 方法规范化：去空白、转大写。{@code null} 返回空串，由 switch 的 default 分支按未知方法处理。 */
  static String normalizeMethod(String method) {
    return method == null ? "" : method.trim().toUpperCase(Locale.ROOT);
  }

  /**
   * 把路径切成小写 token。
   *
   * <p>{@code /api/workflow-runs/{id}/stop} → {@code [api, workflow-runs, workflow, runs, id, stop]}。
   * 同时保留"整段"与"按 {@code -}/{@code _}/{@code .} 拆分后的子词"，使 {@code workflow-runs} 既能被
   * {@code workflow-runs} 命中，也能被 {@code runs} 命中。
   *
   * <p>模板占位符 {@code {id}} 会被剥成 {@code id}，避免大括号干扰匹配。
   *
   * <p>返回不可变集合：调用方（包括护栏）不应能修改推断依据。
   */
  static Set<String> pathTokens(String path) {
    Set<String> tokens = new java.util.LinkedHashSet<>();
    if (path == null || path.isBlank()) {
      return Set.of();
    }
    for (String segment : path.split("/")) {
      String cleaned = segment.trim().toLowerCase(Locale.ROOT);
      if (cleaned.isEmpty()) continue;
      if (cleaned.startsWith("{") && cleaned.endsWith("}")) {
        cleaned = cleaned.substring(1, cleaned.length() - 1);
        if (cleaned.isEmpty()) continue;
      }
      tokens.add(cleaned);
      for (String part : cleaned.split("[-_.]")) {
        if (!part.isEmpty()) {
          tokens.add(part);
        }
      }
    }
    return Set.copyOf(tokens);
  }

  private static boolean intersects(Set<String> tokens, Set<String> keywords) {
    for (String keyword : keywords) {
      if (tokens.contains(keyword)) {
        return true;
      }
    }
    return false;
  }

  /** 路径中是否存在与授权目标绑定的模板参数（{@code {targetId}} 或含 target 的段）。 */
  private static boolean touchesTargetParameter(String path) {
    if (path == null) return false;
    for (String segment : path.split("/")) {
      String cleaned = segment.trim().toLowerCase(Locale.ROOT);
      if (cleaned.startsWith("{") && cleaned.endsWith("}")) {
        cleaned = cleaned.substring(1, cleaned.length() - 1);
      }
      if (cleaned.contains("target")) {
        return true;
      }
    }
    return false;
  }

  /** 参数非空校验的便捷入口，避免调用方散落 {@code Objects.requireNonNull}。 */
  static String describe(String method, String path) {
    return Objects.toString(normalizeMethod(method), "") + " " + Objects.toString(path, "");
  }
}
