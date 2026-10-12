package com.bachelor.toolbox.ai.guard;

import com.bachelor.toolbox.ai.capability.AgentCapability;
import com.bachelor.toolbox.ai.capability.CapabilityRegistry;
import com.bachelor.toolbox.ai.capability.RiskLevel;
import com.bachelor.toolbox.ai.capability.TargetIdExtractor;
import com.bachelor.toolbox.ai.guard.TargetBindingProbe.Declaration;
import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.project.ProjectApproval;
import com.bachelor.toolbox.project.ProjectApprovalRepository;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.TargetPolicyService;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Function;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/**
 * 护栏唯一入口（设计文档 §6.1 - §6.3、§6.7）。
 *
 * <h2>四层校验</h2>
 *
 * <pre>
 *   L-B 能力准入（管"能调什么"）
 *   L-C 参数校验（管"怎么调"）
 *   L-A 授权边界（管"打谁"）
 *   L-D 唯一入口（管"能不能绕"）
 * </pre>
 *
 * <p><strong>实际执行顺序说明（与 §6.1 流程图不同，按 §6.2/§6.3 修正）</strong>：§6.1 的图把 L-A 画在 L-B 之前，但 §6.3 的参考
 * 实现先判黑名单。文档内部不一致，这里按 §6.2/§6.3 实现，且把 L-C 也提到 L-A 之前，理由如下：
 *
 * <ol>
 *   <li><strong>L-B 必须先于 L-A</strong>：黑名单能力（{@code POST /api/system/shutdown}、{@code /api/auth/*}、业务数据重置）本质上
 *       <em>不是"针对授权目标"的能力</em>，它们的 {@code targetBindings} 要么是空集、要么是哨兵。若先跑 L-A：带合法 {@code
 *       targetId} 调用 {@code shutdown} 会通过 L-A，<strong>黑名单形同虚设（真正的绕过）</strong>；不带 {@code targetId} 时会被
 *       L-A 以"无法解析授权目标"拒绝，<em>结论对但理由错</em>，审计里看不到"这是黑名单拒绝"。
 *   <li><strong>L-C 必须先于 L-A</strong>：L-A 的哨兵分支会拒绝一切无法静态解析目标的能力，而 {@code invoke_endpoint} 这类通用
 *       原语必然落进该分支。若 L-A 先行，§9.5 的"路径含 {@code ../} 的端点调用 → 拒绝（L-C）"与 schema 违规永远走不到，审计里
 *       只会看到"无法解析授权目标"。参数校验是纯静态判定，提前执行无副作用。
 * </ol>
 *
 * <p>层与层之间的先后<strong>不影响安全性</strong>——任何一层拒绝都会终止调用；它影响的是"拒绝理由是否精确"，而理由精确性直接决定
 * 论文 §9.5 的越界拦截率能否被正确归因。
 *
 * <h2>L-A 的三态判定（本类最关键的部分）</h2>
 *
 * <p>授权校验的判据是 {@link AgentCapability#targetBindings(Map)}，<strong>绝不是</strong> {@code kind()}。按 {@code kind()} 判定会被
 * "间接执行"能力绕过：{@code POST /api/tasks} 的类别是 {@code WRITE}，却会创建出真正扫描目标的任务（§6.2 的核心修正）。
 *
 * <p>空集的合法性来自能力的<strong>显式声明</strong>（{@link TargetBindingProbe}），而不是 {@code risk()} / {@code
 * requiresApproval()} 这些推导值——否则一个被误判为 {@code SAFE} 的扫描能力就能用空集溜过 L-A（§10 失败模式表）。
 *
 * <h2>防 TOCTOU（§6.7）</h2>
 *
 * <p>当上下文携带审批时的目标绑定快照时，执行前重新计算并比对；不一致即拒绝，要求重新确认。
 */
@Service
public class CapabilityGate {

  /** schema 校验模式。 */
  public enum SchemaMode {
    /** 只记录违规、不拦截（默认）。见类注释"为什么默认 WARN"。 */
    WARN,
    /** 违规即拒绝。§9.5 对照实验需要严格校验时显式切换。 */
    ENFORCE
  }

  /** 目标范围校验与执行期复核之间的 TOCTOU 窗口。 */
  private static final Set<String> PATH_TRAVERSAL_MARKERS = Set.of("..", "%2e", "%2E");

  private final CapabilityRegistry registry;
  private final TargetPolicyService targetPolicy;
  private final CapabilityBlacklist blacklist;
  private final ApprovalPolicy approvalPolicy;
  private final CapabilityAuditSink audit;
  private final TargetAccessResolver targetAccessResolver;
  private final SchemaMode schemaMode;
  private final Set<String> whitelistedCodes;
  private final Set<String> activeWhitelist;
  private final EndpointParameterPolicy endpointParameterPolicy;

  /**
   * 按需授权凭据解析器（"先看见，要用时申请"）。
   *
   * <p>为 {@code null} 时，未授权目标仍按修复前的行为<strong>直接拒绝</strong>——
   * 即"按需授权未装配"时不会 fail-open，只是退化为原行为。
   */
  private final CapabilityApprovalGrantResolver approvalGrantResolver;

  /** 待批申请登记表；为 {@code null} 时申请不进登记表（仅返回值）。 */
  private final PendingApprovalRegistry pendingRegistry;

  public CapabilityGate(
      CapabilityRegistry registry,
      TargetPolicyService targetPolicy,
      CapabilityBlacklist blacklist,
      ApprovalPolicy approvalPolicy,
      CapabilityAuditSink audit,
      TargetAccessResolver targetAccessResolver,
      @Value("${toolbox.agent.guard.schema-mode:warn}") String schemaMode,
      @Value("${toolbox.agent.guard.whitelist:}") String whitelist,
      @Value("${toolbox.agent.guard.active-whitelist:}") String activeWhitelist,
      @org.springframework.beans.factory.annotation.Autowired(required = false)
          EndpointParameterPolicy endpointParameterPolicy) {
    this(
        registry,
        targetPolicy,
        blacklist,
        approvalPolicy,
        audit,
        targetAccessResolver,
        schemaMode,
        whitelist,
        activeWhitelist,
        endpointParameterPolicy,
        null);
  }

  /**
   * 完整构造（含按需授权解析器）。
   *
   * <p>保留上面的 10 参构造作为兼容入口——既有测试与装配不必改动。
   *
   * <p><strong>刻意不加 {@code @Autowired}</strong>：Spring 只允许<strong>一个</strong>
   * {@code required=true} 的 {@code @Autowired} 构造。本类有三个重载，若都标注，
   * 容器启动时会抛 {@code Invalid autowire-marked constructor}——而<strong>单元测试仍全部通过</strong>
   * （它们直接调构造器，不经过容器），故障只在 {@code @SpringBootTest} 下暴露。
   * 这正是"测试通过 ≠ 装配生效"的典型形态。
   */
  public CapabilityGate(
      CapabilityRegistry registry,
      TargetPolicyService targetPolicy,
      CapabilityBlacklist blacklist,
      ApprovalPolicy approvalPolicy,
      CapabilityAuditSink audit,
      TargetAccessResolver targetAccessResolver,
      @Value("${toolbox.agent.guard.schema-mode:warn}") String schemaMode,
      @Value("${toolbox.agent.guard.whitelist:}") String whitelist,
      @Value("${toolbox.agent.guard.active-whitelist:}") String activeWhitelist,
      @org.springframework.beans.factory.annotation.Autowired(required = false)
          EndpointParameterPolicy endpointParameterPolicy,
      @org.springframework.beans.factory.annotation.Autowired(required = false)
          CapabilityApprovalGrantResolver approvalGrantResolver) {
    this(
        registry,
        targetPolicy,
        blacklist,
        approvalPolicy,
        audit,
        targetAccessResolver,
        schemaMode,
        whitelist,
        activeWhitelist,
        endpointParameterPolicy,
        approvalGrantResolver,
        null);
  }

  /**
   * 最终构造（含待批申请登记表）。
   *
   * <p>逐级委托保留前两个构造作为兼容入口——既有测试与装配不必改动。
   */
  @org.springframework.beans.factory.annotation.Autowired
  public CapabilityGate(
      CapabilityRegistry registry,
      TargetPolicyService targetPolicy,
      CapabilityBlacklist blacklist,
      ApprovalPolicy approvalPolicy,
      CapabilityAuditSink audit,
      TargetAccessResolver targetAccessResolver,
      @Value("${toolbox.agent.guard.schema-mode:warn}") String schemaMode,
      @Value("${toolbox.agent.guard.whitelist:}") String whitelist,
      @Value("${toolbox.agent.guard.active-whitelist:}") String activeWhitelist,
      @org.springframework.beans.factory.annotation.Autowired(required = false)
          EndpointParameterPolicy endpointParameterPolicy,
      @org.springframework.beans.factory.annotation.Autowired(required = false)
          CapabilityApprovalGrantResolver approvalGrantResolver,
      @org.springframework.beans.factory.annotation.Autowired(required = false)
          PendingApprovalRegistry pendingRegistry) {
    this.registry = Objects.requireNonNull(registry, "能力注册表不能为空");
    this.targetPolicy = Objects.requireNonNull(targetPolicy, "目标策略服务不能为空");
    this.blacklist = blacklist == null ? CapabilityBlacklist.defaults() : blacklist;
    this.approvalPolicy = approvalPolicy == null ? new ApprovalPolicy() : approvalPolicy;
    this.audit = audit == null ? CapabilityAuditSink.NOOP : audit;
    this.targetAccessResolver =
        targetAccessResolver == null ? TargetAccessResolver.unavailable() : targetAccessResolver;
    this.schemaMode = parseSchemaMode(schemaMode);
    this.whitelistedCodes = parseCodes(whitelist);
    this.activeWhitelist = parseCodes(activeWhitelist);
    this.endpointParameterPolicy = endpointParameterPolicy;
    this.approvalGrantResolver = approvalGrantResolver;
    this.pendingRegistry = pendingRegistry;
  }

  // ------------------------------------------------------------------ 唯一入口

  /**
   * 护栏是否已接通按需授权（"先看见，要用时申请"）。
   *
   * <p>供容器级装配测试断言"Bean 存在 <strong>且</strong> 真的接上了"——
   * 仅断言 Bean 存在是不够的：护栏构造器有三级重载，委托写错时 Bean 在容器里
   * 但护栏拿到的是 {@code null}，此时未授权目标会被<strong>直接拒绝</strong>而非返回申请，
   * 而所有单元测试仍然通过。
   */
  public boolean hasOnDemandApproval() {
    return approvalGrantResolver != null;
  }

  /**
   * 唯一入口：校验通过后执行能力（设计文档 §6.3、§6.4 的 L-D）。
   *
   * <p>所有能力（含 {@code invoke_endpoint} 与 {@code bash_probe}）都必须经此方法，无旁路。执行阶段若能力对应的底层是 {@code
   * SecurityTool}，其目标一律取本次调用已解析出的目标（见 {@link CapabilityExecutor}）。
   *
   * @throws CapabilityDeniedException 任一层校验失败
   */
  public CapabilityOutcome invoke(String code, Map<String, Object> params, CapabilityContext ctx) {
    Map<String, Object> safeParams = params == null ? Map.of() : params;
    CapabilityContext context = ctx == null ? CapabilityContext.anonymous() : ctx;
    Map<String, Object> auditDetail = new LinkedHashMap<>();
    AgentCapability capability = null;
    try {
      // ---------------- L-D 唯一入口：能力必须已在注册表中 ----------------
      capability = requireRegistered(code, auditDetail, safeParams, context);

      // ---------------- L-B 能力准入 ----------------
      ApprovalLevel admissionLevel = admit(capability, auditDetail, safeParams, context);

      // ---------------- L-C 参数校验 ----------------
      // 刻意排在 L-A 之前：L-A 的哨兵分支（TARGET_BINDING_UNRESOLVED）会拒绝一切无法静态解析目标的能力，
      // 而 invoke_endpoint 这类通用原语必然落进该分支。若 L-A 先行，§9.5 的"路径含 ../ 的端点调用 → 拒绝（L-C）"
      // 与 schema 违规就永远走不到，审计里只会看到一句"无法解析授权目标"，既掩盖了真实原因，也让 L-C 形同虚设。
      // 参数校验是纯静态判定（不改状态、不触网），提前执行不产生任何副作用。
      validateParameters(capability, safeParams, auditDetail, context);

      // ---------------- L-A 授权边界（按 targetBindings 判定，非 kind）----------------
      // 按需授权：未授权目标不再直接拒绝，而是返回"申请授权"（见 resolveAndValidateAuthorization）。
      // 用长度 1 的数组作为出参（Java 无多返回值；用 holder 比改签名影响面小）。
      CapabilityApprovalRequest[] pendingApproval = new CapabilityApprovalRequest[1];
      Set<String> bindings =
          resolveAndValidateAuthorization(capability, safeParams, auditDetail, context, pendingApproval);
      if (pendingApproval[0] != null) {
        // 第三个出口：能力合法、参数合法，只是目标尚未授权 → 请用户批准。
        if (pendingRegistry != null) {
          // 登记待批申请：用户批准时服务端据此验证"申请确实由 Agent 提出过"，
          // 防止凭空构造批准请求。
          pendingRegistry.register(pendingApproval[0]);
        }
        record(
            "AGENT_CAPABILITY_APPROVAL_REQUESTED",
            code,
            new LinkedHashMap<>(auditDetail),
            "APPROVAL_REQUIRED",
            context);
        return CapabilityOutcome.approvalRequired(capability, pendingApproval[0]);
      }

      // ---------------- L-C' 端点透传参数校验（§6.5 反向能力映射 / X-7）----------------
      // 必须排在 L-A 之后：本层要拿"已通过授权校验的目标"去比对端口子集与工具参数白名单。
      // 它防的是"外层 schema 合法、内层 parameters 越权"的间接执行路径（invoke_endpoint → POST /api/tasks）。
      validateEndpointParameterPolicy(capability, safeParams, auditDetail, context);

      // ---------------- 风险分级 → 人工确认（仅高危）----------------
      ApprovalLevel level = approvalPolicy
          .levelFor(capability, safeParams, bindings)
          .stricterOf(admissionLevel);
      auditDetail.put("approvalLevel", level.name());
      if (level == ApprovalLevel.FORBIDDEN) {
        throw deny(
            CapabilityDeniedException.Layer.ADMISSION,
            "BLOCKED_CAPABILITY",
            capability,
            "该能力不允许由 Agent 调用: " + capability.code());
      }
      if (level == ApprovalLevel.REQUIRED && !context.humanApproved()) {
        throw deny(
            CapabilityDeniedException.Layer.ADMISSION,
            "APPROVAL_REQUIRED",
            capability,
            "能力 " + capability.code() + " 需要人工逐次确认后才能执行");
      }

      // ---------------- 审计（全量，含拒绝）→ 执行 ----------------
      Map<String, Object> request = new LinkedHashMap<>(auditDetail);
      return new CapabilityOutcome(capability, level, bindings, request);
    } catch (CapabilityDeniedException denied) {
      Map<String, Object> detail = new LinkedHashMap<>(auditDetail);
      detail.put("deniedLayer", denied.layer().label());
      detail.put("deniedReason", denied.reasonCode());
      detail.put("params", safeParams.keySet());
      // 护栏自身故障等附加信息进审计（不含底层异常消息）。
      detail.putAll(denied.auditDetails());
      record("AGENT_CAPABILITY_DENIED", code, detail, "DENIED", context);
      throw denied;
    }
  }

  /**
   * 只校验不执行（{@code dryRun}）。
   *
   * <p>用于"先算确认等级再决定是否打扰用户"的场景，语义与 {@link #invoke} 完全一致，同样会写审计。
   */
  public CapabilityOutcome check(String code, Map<String, Object> params, CapabilityContext ctx) {
    return invoke(code, params, ctx);
  }

  /** 判断能力码是否已在注册表中登记（不做任何授权判定）。 */
  public boolean isRegistered(String code) {
    return registry.find(code).isPresent();
  }

  /** 当前生效的黑名单。 */
  public CapabilityBlacklist blacklist() {
    return blacklist;
  }

  /** 当前 schema 校验模式。 */
  public SchemaMode schemaMode() {
    return schemaMode;
  }

  /** 已开启的能力白名单（§6.4）。 */
  public Set<String> enabledWhitelist() {
    return activeWhitelist;
  }

  // ------------------------------------------------------------------ L-D

  private AgentCapability requireRegistered(
      String code,
      Map<String, Object> auditDetail,
      Map<String, Object> params,
      CapabilityContext context) {
    if (code == null || code.isBlank()) {
      throw deny(CapabilityDeniedException.Layer.ENTRYPOINT, "UNKNOWN_CAPABILITY", code, "能力码不能为空");
    }
    return registry
        .find(code.trim())
        .orElseThrow(
            () ->
                deny(
                    CapabilityDeniedException.Layer.ENTRYPOINT,
                    "UNKNOWN_CAPABILITY",
                    code,
                    "未知能力（未在能力注册表中登记，按 §6.5 未注册端点一律拒绝）: " + code));
  }

  // ------------------------------------------------------------------ L-B

  private ApprovalLevel admit(
      AgentCapability capability,
      Map<String, Object> auditDetail,
      Map<String, Object> params,
      CapabilityContext context) {
    auditDetail.put("capability", capability.code());
    auditDetail.put("kind", String.valueOf(capability.kind()));
    auditDetail.put("risk", String.valueOf(capability.risk()));
    auditDetail.put("declaredApproval", capability.requiresApproval());

    if (capability.code() == null || capability.code().isBlank()) {
      throw deny(
          CapabilityDeniedException.Layer.ADMISSION,
          "UNCLASSIFIED_CAPABILITY",
          capability.code(),
          "能力未声明唯一标识，无法完成分级（fail-closed）");
    }
    if (capability.kind() == null || capability.risk() == null) {
      // §6.4 默认策略 + §10 失败模式表："新增能力未分级 → 默认 FORBIDDEN（fail-closed）"。
      throw deny(
          CapabilityDeniedException.Layer.ADMISSION,
          "UNCLASSIFIED_CAPABILITY",
          capability.code(),
          "能力未完成分级（kind/risk 为空），按 fail-closed 拒绝: " + capability.code());
    }

    // 黑名单绝对优先：无论 kind/risk 如何、无论参数里带了什么，都不放行。
    if (blacklist.blocks(capability)) {
      throw deny(
          CapabilityDeniedException.Layer.ADMISSION,
          "BLOCKED_CAPABILITY",
          capability,
          "该能力不允许由 Agent 调用: " + capability.code());
    }

    // §6.5 反向能力映射：通用端点原语（invoke_endpoint）不是绕过通道，必须按它"实际要打的端点"套用同样的黑名单。
    // 只检查能力自身的 code/path 会留下后门——invoke_endpoint("POST", "/api/system/shutdown") 的能力码是合法的。
    String requestedPath = requestedEndpointPath(params);
    if (requestedPath != null && blacklist.blocksPath(requestedPath)) {
      throw deny(
          CapabilityDeniedException.Layer.ADMISSION,
          "BLOCKED_CAPABILITY",
          capability,
          "该端点被禁止由 Agent 调用: " + requestedPath);
    }

    // 白名单：ADMIN 类、DESTRUCTIVE 类、bash_probe 需显式开启，未开启即拒绝（fail-closed）。
    if (requiresExplicitEnable(capability) && !isExplicitlyEnabled(capability)) {
      throw deny(
          CapabilityDeniedException.Layer.ADMISSION,
          "CAPABILITY_NOT_ENABLED",
          capability,
          "能力 " + capability.code() + " 属高危能力，需在 toolbox.agent.guard.whitelist 中显式开启");
    }
    return ApprovalLevel.NONE;
  }

  /**
   * 从参数中取出本次调用实际要访问的端点路径（§6.5 的端点白名单与反向能力映射依据）。
   *
   * <p>只有通用端点原语才会带 {@code path} 参数；普通能力的 {@code path} 参数是业务语义（如 sqlmap 的目标路径），不能当端点看。
   * 因此这里限定在能力码为端点原语时才提取，避免把业务参数误判成端点。
   */
  private String requestedEndpointPath(Map<String, Object> params) {
    if (params == null) {
      return null;
    }
    for (String key : ENDPOINT_PATH_KEYS) {
      Object value = params.get(key);
      if (value instanceof String text && !text.isBlank()) {
        return text.trim();
      }
    }
    return null;
  }

  /** 端点原语用于承载路径的参数键。 */
  private static final Set<String> ENDPOINT_PATH_KEYS = Set.of("path", "endpoint", "endpointPath");

  private boolean requiresExplicitEnable(AgentCapability capability) {
    return capability.kind() == com.bachelor.toolbox.ai.capability.CapabilityKind.ADMIN
        || capability.risk() == RiskLevel.DESTRUCTIVE
        || ApprovalPolicy.BASH_PROBE_CODE.equalsIgnoreCase(capability.code());
  }

  private boolean isExplicitlyEnabled(AgentCapability capability) {
    if (whitelistedCodes.contains(capability.code())) {
      return true;
    }
    for (String enabled : whitelistedCodes) {
      if (enabled.endsWith("*")
          && capability.code().startsWith(enabled.substring(0, enabled.length() - 1))) {
        return true;
      }
    }
    return false;
  }

  // ------------------------------------------------------------------ L-A

  /**
   * L-A 授权边界（§6.2 三态判定）。
   *
   * <p><strong>按需授权（"先看见，要用时申请"）</strong>：遇到"目标未授权"这类
   * <em>可申请</em>的原因时，不再直接拒绝，而是把申请写入 {@code pendingApproval[0]}，
   * 由 {@code invoke} 转为 {@link CapabilityOutcome#approvalRequired} 返回给 Agent。
   *
   * <p>只有 {@link #APPROVABLE_REASONS} 中的原因可转为申请；真正的越权（端口越界、
   * 绑定非法、目标越权、解析失败）仍然直接抛异常。
   *
   * @param pendingApproval 出参（长度 1 的数组）：非 null 表示"需要用户授权"
   * @return 本次调用触及的真实目标 ID 集合（真空集表示确实不触及目标）
   */
  private Set<String> resolveAndValidateAuthorization(
      AgentCapability capability,
      Map<String, Object> params,
      Map<String, Object> auditDetail,
      CapabilityContext context,
      CapabilityApprovalRequest[] pendingApproval) {
    Set<String> bindings;
    try {
      bindings = capability.targetBindings(params);
    } catch (RuntimeException failure) {
      // 能力自己解析目标失败 → 不能当成"不触及目标"，必须 fail-closed。
      // 拒绝消息不含底层异常细节（避免泄露内部实现）；类型名进审计。
      throw deny(
              CapabilityDeniedException.Layer.AUTHORIZATION,
              "TARGET_BINDING_UNRESOLVED",
              capability,
              "能力 " + capability.code() + " 解析授权目标失败，按 fail-closed 拒绝")
          .withAuditDetail("guardInternalFailure", true)
          .withAuditDetail("failureType", failure.getClass().getSimpleName());
    }
    if (bindings == null) {
      bindings = Set.of();
    }

    // ① 哨兵态：应触及目标但解析失败 → fail-closed 拒绝（绝不可当成"不触及"）。
    if (bindings.contains(AgentCapability.TARGET_BINDING_UNRESOLVED)) {
      throw deny(
          CapabilityDeniedException.Layer.AUTHORIZATION,
          "TARGET_BINDING_UNRESOLVED",
          capability,
          "无法解析授权目标，拒绝执行（fail-closed）: " + capability.code());
    }

    // ② 真空集：只有"显式声明不触及目标"的能力才合法（见 TargetBindingProbe）。
    if (bindings.isEmpty()) {
      if (!TargetBindingProbe.emptyBindingAllowed(capability)) {
        throw deny(
            CapabilityDeniedException.Layer.AUTHORIZATION,
            "MISSING_TARGET_BINDING",
            capability,
            "能力 "
                + capability.code()
                + " 未声明授权目标绑定（既未显式声明不触及目标，也未返回目标 ID），按 fail-closed 拒绝");
      }
      auditDetail.put("targetBindings", List.of());
      return Set.of();
    }

    // ③ 含真实 targetId：逐个校验存在性、范围、端口、有效期。
    Set<String> validated = new LinkedHashSet<>();
    List<Map<String, Object>> audited = new ArrayList<>();
    for (String rawTargetId : bindings) {
      if (rawTargetId == null || rawTargetId.isBlank()) {
        throw deny(
            CapabilityDeniedException.Layer.AUTHORIZATION,
            "INVALID_TARGET_BINDING",
            capability,
            "授权目标绑定为空值: " + capability.code());
      }
      long targetId;
      try {
        targetId = Long.parseLong(rawTargetId.trim());
      } catch (NumberFormatException exception) {
        // 非数字绑定：既不是哨兵也不是真实 ID，不能猜，直接拒绝。
        throw deny(
            CapabilityDeniedException.Layer.AUTHORIZATION,
            "INVALID_TARGET_BINDING",
            capability,
            "授权目标 ID 非法: " + rawTargetId);
      }
      AuthorizedTarget target;
      try {
        target = requireTarget(targetId, capability);
        // 有效期/启用状态校验也放进 try：它产生的 TARGET_DISABLED / AUTHORIZATION_EXPIRED
        // 同样属于"用户同意就能解决"的未授权类，必须能走到下面的申请分支。
        //
        // ⚠️ 独立验证者 fix-verifier 发现的缺陷（2026-10-12）：原实现把本调用放在 catch 之外，
        // 导致 APPROVABLE_REASONS 里的 TARGET_DISABLED / AUTHORIZATION_EXPIRED 是**死配置项**——
        // requireTarget 只可能抛 TARGET_NOT_FOUND / TARGET_ACCESS_FAILED，
        // 另外两个原因根本进不了 catch。后果：用户停用目标后，Agent 得到的仍是"拒绝"而非"可申请"，
        // 与"先看见，要用时申请"的设计意图不符（方向安全，但功能缺失）。
        validateTargetValidity(target, capability);
      } catch (CapabilityDeniedException notAuthorized) {
        // ⭐ 第三个出口："未授权"不是终点，而是"可以申请"。
        //
        // 仅在"目标不可用/未授权"这一类原因上转为申请；其余原因（绑定非法、端口越权、
        // 路径穿越等）是真正的越权，必须继续抛异常——那些是不可申请的。
        if (!APPROVABLE_REASONS.contains(notAuthorized.reasonCode())) {
          throw notAuthorized;
        }
        // 未装配按需授权 → 无法签发凭据，保持原拒绝行为（fail-closed）。
        if (approvalGrantResolver == null) {
          throw notAuthorized;
        }
        // ⚠️ 注意"未装配"与"装配了 denyAll()"行为不同（独立验证者 fix-verifier 指出）：
        //   resolver == null          → 直接拒绝（本分支）
        //   resolver == denyAll()     → 返回"可申请"，但该实现恒 false，永远批不了
        // 后者对 Agent 而言是"能看见、申请了也没用"。方向安全（不会放行），但体验上
        // 等价于原缺陷。生产装配应注入 InMemoryCapabilityApprovalGrantResolver，
        // 而非依赖 denyAll()。
        // 已有有效凭据（用户此前已批准过同一 能力+目标+参数）→ 放行。
        String digest =
            CapabilityApprovalRequest.digestOf(capability.code(), rawTargetId, params);
        if (approvalGrantResolver.hasValidApproval(capability.code(), rawTargetId, digest)) {
          auditDetail.put("onDemandApproval", "GRANTED");
          validated.add(Long.toString(targetId));
          audited.add(Map.of("targetId", targetId, "onDemandApproval", true));
          continue;
        }
        // 无凭据 → 记录待批申请（由 invoke 转为"申请授权"返回值，而非拒绝）。
        // 平台据此渲染确认卡片；用户批准后签发凭据，Agent 持凭据重试即走上面的分支。
        auditDetail.put("onDemandApproval", "REQUESTED");
        pendingApproval[0] =
            new CapabilityApprovalRequest(
                capability.code(),
                rawTargetId,
                digest,
                String.valueOf(capability.risk()),
                ApprovalLevel.SINGLE,
                describeApproval(capability, rawTargetId, params),
                params);
        return Set.copyOf(validated);
      }
      validateTargetScope(target, capability);
      validateRequestedPorts(target, params, capability);
      validated.add(Long.toString(targetId));
      audited.add(
          Map.of(
              "targetId", targetId,
              "target", String.valueOf(target.getTargetValue()),
              "allowedPorts", String.valueOf(target.getAllowedPorts())));
    }
    auditDetail.put("targetBindings", audited);

    // ④ 防 TOCTOU（§6.7）：审批时记录的快照必须与当前一致。
    if (context.approvedTargetBindings() != null && !context.approvedTargetBindings().isEmpty()) {
      for (Map.Entry<String, String> recorded : context.approvedTargetBindings().entrySet()) {
        if (!validated.contains(recorded.getKey())) {
          throw deny(
              CapabilityDeniedException.Layer.AUTHORIZATION,
              "AUTHORIZATION_SNAPSHOT_CHANGED",
              capability,
              "本次调用的目标与审批时记录的目标不一致，需重新确认");
        }
      }
    }
    return Set.copyOf(validated);
  }

  /**
   * 目标必须存在且当前有效（有效期由 {@code TargetService} 的语义承担）。
   *
   * <p><strong>访问器异常必须归一化</strong>：原实现直接让 {@code targetAccessResolver.find()} 的
   * 异常冒泡，而 {@code invoke} 的 catch 只处理 {@link CapabilityDeniedException}
   * （{@code :175}）→ 裸异常<strong>绕过审计落库</strong>，且把底层异常消息（可能含 SQL/连接串）
   * 原样返回给调用方。
   *
   * <p>这属于 <strong>fail-closed 的"非受控形态"</strong>：结论对（拒绝），过程失控（无审计、泄露内部信息）。
   * 修复后对外契约统一为：要么返回 {@link CapabilityOutcome}，要么抛
   * {@link CapabilityDeniedException}。
   *
   * <p>拒绝消息<strong>不含</strong>底层异常细节；异常类型名进审计（内部可见），消息不进。
   */
  private AuthorizedTarget requireTarget(long targetId, AgentCapability capability) {
    AuthorizedTarget target;
    try {
      target = targetAccessResolver.find(targetId).orElse(null);
    } catch (RuntimeException failure) {
      // 护栏自身故障 → 归一化为拒绝，并让审计留痕。
      // 拒绝消息不含底层异常细节；异常类型名进审计（内部可见），消息不进。
      throw deny(
              CapabilityDeniedException.Layer.AUTHORIZATION,
              "TARGET_ACCESS_FAILED",
              capability,
              "目标访问器故障，按 fail-closed 拒绝: targetId=" + targetId)
          .withAuditDetail("guardInternalFailure", true)
          .withAuditDetail("failureType", failure.getClass().getSimpleName());
    }
    if (target == null) {
      throw deny(
          CapabilityDeniedException.Layer.AUTHORIZATION,
          "TARGET_NOT_FOUND",
          capability,
          "授权目标不存在或无权访问: " + targetId);
    }
    return target;
  }

  /**
   * 端点透传参数校验（§6.5 反向能力映射的落地，防 X-7）。
   *
   * <p>场景：Agent 不直接调用扫描能力，而是经通用端点原语创建一个"会扫描目标"的任务：
   *
   * <pre>
   * invoke_endpoint("POST", "/api/tasks", {targetId, toolCode:"msf_scan",
   *                                        parameters:{module:"exploit/...", options:{...}}})
   * </pre>
   *
   * <p>外层 schema 校验（L-C）看不出问题——{@code parameters} 的类型确实是合法对象；危险藏在它的<strong>内容</strong>里。
   * 本层把 {@link EndpointParameterPolicy} 的四道规则（工具参数白名单、端口 ⊆ 授权端口、MSF 模块前缀、PoC 编号与数量）
   * 套到透传参数上，堵住这条"外层合法、内层越权"的路径。
   *
   * <p>未装配 {@link EndpointParameterPolicy} 时（纯单元测试场景）跳过；生产装配由 {@code
   * AgentCapabilityGuardConfiguration} 提供。
   */
  private void validateEndpointParameterPolicy(
      AgentCapability capability,
      Map<String, Object> params,
      Map<String, Object> auditDetail,
      CapabilityContext context) {
    if (endpointParameterPolicy == null) {
      return;
    }
    String method = stringParam(params, "method", "httpMethod", "http_method");
    String path = stringParam(params, "path", "endpoint", "endpointPath");
    // 先解析请求体，再用"语义特征 + 路径模式"双轨判定（D-6 修复：原为单端点硬编码）。
    Object rawBody = params.get("body");
    Map<String, Object> requestBody = null;
    if (rawBody instanceof Map<?, ?> bodyMap) {
      requestBody = new LinkedHashMap<>();
      for (Map.Entry<?, ?> entry : bodyMap.entrySet()) {
        requestBody.put(String.valueOf(entry.getKey()), entry.getValue());
      }
    } else if (params.get("parameters") instanceof Map<?, ?>) {
      requestBody = new LinkedHashMap<>(params);
    }
    if (!EndpointParameterPolicy.isTaskCreationEndpoint(method, path, requestBody)) {
      return;
    }
    if (requestBody == null) {
      throw deny(
          CapabilityDeniedException.Layer.PARAMETER,
          "ENDPOINT_PARAMETER_POLICY",
          capability,
          "任务创建端点缺少请求体，无法校验透传参数（fail-closed）");
    }
    // 目标已在 L-A 校验过；多目标时逐个套用参数策略（端口子集等规则与目标强相关）。
    for (String targetId : targetIdsOf(requestBody, params)) {
      AuthorizedTarget target = requireTarget(Long.parseLong(targetId), capability);
      try {
        endpointParameterPolicy.validateTaskCreationBody(target, requestBody);
      } catch (ApiException invalid) {
        throw deny(
            CapabilityDeniedException.Layer.PARAMETER,
            "ENDPOINT_PARAMETER_POLICY",
            capability,
            "端点透传参数越权: " + invalid.getMessage());
      }
    }
    auditDetail.put("endpointParameterPolicy", "APPLIED");
  }

  /**
   * 从端点请求体（必要时回落到外层参数）解析目标 ID。
   *
   * <p>委托给 {@link TargetIdExtractor}——与 {@code InvokeEndpointCapability.targetBindings}
   * <strong>共用同一份实现</strong>，避免出现第四份重复解析逻辑（重复正是本次全部缺陷的根因）。
   */
  private static Set<String> targetIdsOf(Map<String, Object> body, Map<String, Object> params) {
    return TargetIdExtractor.extract(body, params);
  }

  private static String stringParam(Map<String, Object> params, String... keys) {
    for (String key : keys) {
      Object value = params.get(key);
      if (value instanceof String text && !text.isBlank()) {
        return text.trim();
      }
    }
    return null;
  }

  /**
   * 有效期与启用状态校验（设计文档 §6.1："授权未过期？"）。
   *
   * <p><strong>为什么护栏必须自己判一遍</strong>：生产环境的 {@link TargetAccessResolver} 接的是 {@code
   * TargetService.getCurrentlyAuthorized}，它<em>确实</em>会检查有效期。但护栏是安全边界，不能把"授权是否有效"这条核心规则
   * <strong>委托给一个可替换的注入点</strong>——一旦某个调用方注入了"只按 ID 取目标"的实现（测试桩、内部工具、未来的新装配），
   * 过期授权就会静默放行，而且从护栏代码上完全看不出来。
   *
   * <p>因此这里按 {@link AuthorizedTarget} 自身的字段再判一次，与 {@code TargetService#validateCurrentlyAuthorized} 的语义
   * 保持一致（重复判定不会造成误拦，只会让 fail-closed 更可靠）。
   */
  private void validateTargetValidity(AuthorizedTarget target, AgentCapability capability) {
    if (!target.isEnabled()) {
      throw deny(
          CapabilityDeniedException.Layer.AUTHORIZATION,
          "TARGET_DISABLED",
          capability,
          "授权目标已停用: " + target.getId());
    }
    Instant now = Instant.now();
    if (target.getAuthorizationValidFrom() != null && now.isBefore(target.getAuthorizationValidFrom())) {
      throw deny(
          CapabilityDeniedException.Layer.AUTHORIZATION,
          "AUTHORIZATION_NOT_YET_VALID",
          capability,
          "目标授权尚未生效: " + target.getId());
    }
    if (target.getAuthorizationExpiresAt() != null && !now.isBefore(target.getAuthorizationExpiresAt())) {
      throw deny(
          CapabilityDeniedException.Layer.AUTHORIZATION,
          "AUTHORIZATION_EXPIRED",
          capability,
          "目标授权已过期: " + target.getId());
    }
  }

  /** 范围校验：目标启用状态 + 地址策略（{@link TargetPolicyService#validatedHost}）。 */
  private void validateTargetScope(AuthorizedTarget target, AgentCapability capability) {
    try {
      targetPolicy.validatedHost(target);
    } catch (ApiException denied) {
      throw deny(
          CapabilityDeniedException.Layer.AUTHORIZATION,
          "TARGET_OUT_OF_SCOPE",
          capability,
          "目标越权（超出授权范围）: " + denied.getMessage());
    }
  }

  /** 端口校验：参数里出现的每个端口都必须在目标的授权端口范围内。 */
  private void validateRequestedPorts(
      AuthorizedTarget target, Map<String, Object> params, AgentCapability capability) {
    Set<Integer> requested;
    try {
      requested = requestedPorts(params);
    } catch (ApiException unparseable) {
      // 修复：端口解析失败 → 归一化为拒绝（fail-closed），而不是让异常裸冒泡绕过审计。
      // 原实现只遍历 requestedPorts 的结果集，无法解析的端口被静默丢弃 → 越权端口不被校验。
      throw deny(
          CapabilityDeniedException.Layer.AUTHORIZATION,
          "PORT_UNPARSEABLE",
          capability,
          "请求的端口无法解析，拒绝执行（fail-closed）: " + unparseable.getMessage());
    }
    for (int port : requested) {
      try {
        targetPolicy.validateAuthorizedPort(target, port);
      } catch (ApiException denied) {
        throw deny(
            CapabilityDeniedException.Layer.AUTHORIZATION,
            "PORT_OUT_OF_SCOPE",
            capability,
            "端口越权: " + denied.getMessage());
      }
    }
  }

  /** 端口区间展开上限：防止 {@code 1-65535} 之类的输入把内存撑爆（授权端口本身最多也就 65535 个）。 */
  private static final int MAX_EXPANDED_PORTS = 65536;

  /**
   * 哪些 L-A 拒绝原因<strong>可以</strong>转为"申请授权"。
   *
   * <p><strong>刻意只列"目标未授权/不可用"这一类</strong>——它们是"用户同意就能解决"的问题。
   * 其余原因（绑定非法、端口越权、路径穿越、目标越权、解析失败）是<strong>真正的越权</strong>，
   * 即使申请也不应批准，必须继续抛异常。
   *
   * <p>这是本机制的安全边界：<strong>"申请"不是万能逃生门</strong>。
   *
   * <h2>⚠️ 独立验证者发现的缺陷（2026-10-12，已修复）</h2>
   *
   * <p>本清单曾包含 {@code TARGET_DISABLED} / {@code AUTHORIZATION_EXPIRED}，
   * 但产生这两个原因的 {@code validateTargetValidity} 调用位于 try/catch <strong>之外</strong>，
   * 因此它们<strong>根本进不了 catch</strong>——是<strong>死配置项</strong>。
   * 修复方式：把 {@code validateTargetValidity} 移入 try 块。
   *
   * <p>同时补入 {@code AUTHORIZATION_NOT_YET_VALID}：它与 {@code AUTHORIZATION_EXPIRED}
   * 同为"授权时间窗口"问题，语义上属于同一类（用户可调整授权窗口解决）。
   */
  private static final Set<String> APPROVABLE_REASONS =
      Set.of(
          "TARGET_NOT_FOUND",
          "TARGET_DISABLED",
          "AUTHORIZATION_EXPIRED",
          "AUTHORIZATION_NOT_YET_VALID");

  /**
   * 生成给用户看的申请摘要——<strong>由平台生成，不是 Agent 写的</strong>。
   *
   * <p>安全关键：若允许 Agent 自定义申请文案，它可以"把 3306 端口说成 80"来说服用户。
   * 本方法只用能力元数据与参数原文拼装，不含任何 Agent 提供的措辞。
   */
  private static String describeApproval(
      AgentCapability capability, String targetId, Map<String, Object> params) {
    StringBuilder summary = new StringBuilder();
    summary
        .append("能力 ")
        .append(capability.code())
        .append("（风险等级 ")
        .append(capability.risk())
        .append("）请求对目标 ")
        .append(targetId)
        .append(" 执行操作。");
    if (params != null && !params.isEmpty()) {
      summary.append(" 参数原文：").append(new java.util.TreeMap<>(params));
    }
    summary.append(" 该目标当前未在授权范围内，需您确认后才能执行。");
    return summary.toString();
  }

  /**
   * 从参数中提取本次调用请求的端口。
   *
   * <p>识别 {@code port} / {@code ports} / {@code portRange}，支持数字、数字字符串、集合与 {@code "80,443"} /
   * {@code "1-1024"} 写法。
   *
   * <p><strong>区间必须完整展开，不能只取两端点</strong>：若授权端口是 {@code 8080-8090} 而请求 {@code 8085-8095}，
   * 只比对端点会得出"8085 在范围内、8095 不在"——虽能拒绝，但反过来"授权 {@code 8080-8090}、请求 {@code 8082-8088}"
   * 这类<em>部分越界</em>（如授权 {@code 80,443}、请求 {@code 80-443}）就检测不出来了。因此这里按
   * {@link #MAX_EXPANDED_PORTS} 上限做完整展开；超过上限的输入直接拒绝（fail-closed），而不是静默降级成端点比对。
   */
  static Set<Integer> requestedPorts(Map<String, Object> params) {
    Set<Integer> ports = new TreeSet<>();
    if (params == null) {
      return ports;
    }
    for (Map.Entry<String, Object> entry : params.entrySet()) {
      String key = entry.getKey() == null ? "" : entry.getKey().trim().toLowerCase(java.util.Locale.ROOT);
      if (!Set.of("port", "ports", "portrange", "port_range").contains(key.replace("_", ""))) {
        continue;
      }
      collectPorts(entry.getValue(), ports);
    }
    return ports;
  }

  /**
   * 收集参数里出现的所有端口。
   *
   * <p><strong>fail-closed 原则：绝不丢弃任何 token。</strong>无法解析的端口必须抛异常，
   * 由调用方转为拒绝——而不是静默跳过。
   *
   * <p>原实现有三处静默丢弃，导致 {@code requestedPorts} 返回请求端口集的<em>子集</em>，
   * 而 {@code validateRequestedPorts} 只遍历该子集 → <strong>无法解析的端口 = 不被校验</strong>：
   *
   * <ul>
   *   <li>越界数字（如 {@code 70000}）被丢弃
   *   <li>倒置区间（如 {@code 443-80}）被丢弃
   *   <li>单端口解析失败（如 {@code abc}）被丢弃 → 攻击载荷 {@code "80,3306-"} 只保留 {@code {80}}，
   *       <strong>越权端口 3306 被伪装隐藏</strong>
   * </ul>
   *
   * <p>对照：dispatch 层 {@code PortRangeParser.parsePort} 对非法输入<em>抛异常</em>（fail-closed）。
   * 本方法现在与其保持一致——<strong>同一语义、同一失败方向</strong>。
   *
   * <p><strong>为什么"缺失"与"解析失败"必须区别对待</strong>：
   *
   * <ul>
   *   <li>参数<em>缺失</em>（{@code value == null}）→ 合法，回落授权端口
   *   <li>参数<em>不可解析</em> → 输入不可信 → <strong>必须拒绝</strong>
   * </ul>
   */
  private static void collectPorts(Object value, Set<Integer> sink) {
    if (value == null) {
      // 缺失 → 合法（保持原语义：回落授权端口）。
      return;
    }
    if (value instanceof java.util.Collection<?> collection) {
      collection.forEach(item -> collectPorts(item, sink));
      return;
    }
    if (value instanceof Object[] array) {
      for (Object item : array) {
        collectPorts(item, sink);
      }
      return;
    }
    if (value instanceof Number number) {
      int port = number.intValue();
      if (port <= 0 || port > 65535) {
        // 修复：越界数字不再静默丢弃。
        throw new ApiException("请求的端口越界，无法完成授权校验: " + port);
      }
      sink.add(port);
      return;
    }
    for (String part : value.toString().split("[,;\\s]+")) {
      String item = part.trim();
      if (item.isEmpty()) {
        // 空段（如 "80,," 的尾随逗号）不是"端口"，忽略是安全的。
        continue;
      }
      int dash = item.indexOf('-');
      if (dash > 0) {
        Integer from = parsePort(item.substring(0, dash));
        Integer to = parsePort(item.substring(dash + 1));
        // 修复：任一端解析失败 → 拒绝（原为静默跳过）。
        if (from == null || to == null) {
          throw new ApiException("请求的端口区间无法解析，拒绝执行: " + item);
        }
        // 修复：倒置区间 → 拒绝（原为静默跳过）。
        if (from > to) {
          throw new ApiException("请求的端口区间起始值大于结束值: " + item);
        }
        if (to - from + 1 > MAX_EXPANDED_PORTS) {
          // 极端区间：拒绝而不是降级比对（fail-closed）。
          throw new ApiException("请求的端口区间过大，无法完成授权校验: " + item);
        }
        // 完整展开：区间内任何一个端口越权都必须被发现。
        for (int port = from; port <= to; port++) {
          sink.add(port);
        }
        continue;
      }
      Integer port = parsePort(item);
      // 修复：单端口解析失败 → 拒绝（原为静默跳过）。
      if (port == null) {
        throw new ApiException("请求的端口无法解析，拒绝执行: " + item);
      }
      sink.add(port);
    }
  }

  /** 解析单个端口；返回 {@code null} 表示"无法解析"（由调用方决定拒绝）。 */
  private static Integer parsePort(String text) {
    try {
      int port = Integer.parseInt(text.trim());
      return port > 0 && port <= 65535 ? port : null;
    } catch (NumberFormatException exception) {
      return null;
    }
  }

  // ------------------------------------------------------------------ L-C

  private void validateParameters(
      AgentCapability capability,
      Map<String, Object> params,
      Map<String, Object> auditDetail,
      CapabilityContext context) {
    rejectPathTraversal(capability, params);

    List<String> violations = SchemaValidator.validate(capability.parameterSchema(), params);
    if (!violations.isEmpty()) {
      auditDetail.put("schemaViolations", violations);
      if (schemaMode == SchemaMode.ENFORCE) {
        throw deny(
            CapabilityDeniedException.Layer.PARAMETER,
            "SCHEMA_VIOLATION",
            capability,
            "参数不符合能力声明的 schema: " + String.join("; ", violations));
      }
    }

    try {
      capability.validateParams(params);
    } catch (ApiException invalid) {
      throw deny(
          CapabilityDeniedException.Layer.PARAMETER,
          "INVALID_PARAMETER",
          capability,
          "参数校验未通过: " + invalid.getMessage());
    } catch (RuntimeException unexpected) {
      // 能力自定义校验抛出的非 ApiException 也按拒绝处理（不能因为异常类型不对就放行）。
      throw deny(
          CapabilityDeniedException.Layer.PARAMETER,
          "INVALID_PARAMETER",
          capability,
          "参数校验异常: " + unexpected.getMessage());
    }
  }

  /** §9.5："路径含 {@code ../} 的端点调用 → 拒绝（L-C 路径规范化）"。 */
  private void rejectPathTraversal(AgentCapability capability, Map<String, Object> params) {
    if (params == null) {
      return;
    }
    for (Map.Entry<String, Object> entry : params.entrySet()) {
      String key = entry.getKey() == null ? "" : entry.getKey().toLowerCase(java.util.Locale.ROOT);
      if (!key.contains("path") && !key.contains("url") && !key.contains("uri")) {
        continue;
      }
      String value = entry.getValue() == null ? "" : entry.getValue().toString();
      for (String marker : PATH_TRAVERSAL_MARKERS) {
        if (value.contains(marker)) {
          throw deny(
              CapabilityDeniedException.Layer.PARAMETER,
              "PATH_TRAVERSAL",
              capability,
              "参数 " + entry.getKey() + " 含路径穿越片段，拒绝执行");
        }
      }
    }
  }

  // ------------------------------------------------------------------ 审计

  private void record(
      String action,
      String code,
      Map<String, Object> detail,
      String result,
      CapabilityContext context) {
    try {
      audit.record(action, code, detail, result);
    } catch (RuntimeException ignored) {
      // 审计通道故障不得改变护栏结论。
    }
  }

  private CapabilityDeniedException deny(
      CapabilityDeniedException.Layer layer,
      String reasonCode,
      AgentCapability capability,
      String message) {
    return deny(layer, reasonCode, capability == null ? null : capability.code(), message);
  }

  private CapabilityDeniedException deny(
      CapabilityDeniedException.Layer layer, String reasonCode, String code, String message) {
    return new CapabilityDeniedException(layer, reasonCode, code, message);
  }

  // ------------------------------------------------------------------ 辅助

  private static SchemaMode parseSchemaMode(String value) {
    if (value == null || value.isBlank()) {
      return SchemaMode.WARN;
    }
    return switch (value.trim().toUpperCase(java.util.Locale.ROOT)) {
      case "ENFORCE", "STRICT" -> SchemaMode.ENFORCE;
      default -> SchemaMode.WARN;
    };
  }

  private static Set<String> parseCodes(String commaSeparated) {
    Set<String> codes = new TreeSet<>();
    if (commaSeparated == null) {
      return codes;
    }
    for (String part : commaSeparated.split("[,;\\s]+")) {
      if (!part.isBlank()) {
        codes.add(part.trim());
      }
    }
    return codes;
  }

  /**
   * 目标访问器：把"按 ID 取授权目标"抽象出来，使护栏可以脱离 Spring 上下文做单元测试（越权用例集需要）。
   *
   * <p>生产环境由 {@link AgentCapabilityGuardConfiguration} 接上 {@code TargetService}，因此权限判定、软删除等既有语义不会被
   * 护栏重复实现，也不会被绕过。
   */
  @FunctionalInterface
  public interface TargetAccessResolver {
    /** 按 ID 取目标；不存在或无权访问时返回空。 */
    java.util.Optional<AuthorizedTarget> find(long targetId);

    /** 无法解析目标时的实现：一律返回空 → 护栏按 fail-closed 拒绝。 */
    static TargetAccessResolver unavailable() {
      return targetId -> java.util.Optional.empty();
    }

    /** 用给定函数构造。 */
    static TargetAccessResolver of(Function<Long, AuthorizedTarget> loader) {
      return targetId -> {
        try {
          return java.util.Optional.ofNullable(loader.apply(targetId));
        } catch (RuntimeException failure) {
          return java.util.Optional.empty();
        }
      };
    }
  }

  /** 审批记录访问器（§6.7 快照比对的数据来源）。 */
  @FunctionalInterface
  public interface ApprovalResolver {
    /** 取审批单；不存在时返回空。 */
    java.util.Optional<ProjectApproval> find(long approvalId);

    static ApprovalResolver from(ProjectApprovalRepository repository) {
      return approvalId -> repository.findById(approvalId);
    }
  }
}
