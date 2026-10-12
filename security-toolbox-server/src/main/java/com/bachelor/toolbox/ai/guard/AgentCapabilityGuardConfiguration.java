package com.bachelor.toolbox.ai.guard;

import com.bachelor.toolbox.ai.capability.AgentCapability;
import com.bachelor.toolbox.ai.capability.CapabilityRegistry;
import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.project.ProjectAuthorizationService;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.TargetService;
import java.util.Set;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * 护栏装配（设计文档 §6.4 黑名单配置、§6.8 复用现有基础设施）。
 *
 * <p>本配置<strong>只</strong>提供护栏自己的协作者（黑名单、审计出口、目标访问器、审批访问器），刻意不重新定义 {@link
 * CapabilityRegistry}——原因见 {@link #capabilityBlacklist} 的注释（重名 + 循环依赖两处启动期硬失败）。
 *
 * <p>装配正确性由容器测试 {@code CapabilityGateConfigurationTest} 覆盖：task-1 的实测教训是"Spring 装配错误单元测试全绿也抓不到"。
 */
@Configuration
public class AgentCapabilityGuardConfiguration {

  /**
   * 黑名单：§6.4 默认表 + 可配置追加。
   *
   * <p>这是护栏对"什么被禁止"的<strong>唯一策略来源</strong>。{@link CapabilityRegistry} 的 Javadoc 明确写道："黑名单配置数据由
   * 治理层（护栏 L-B）提供，通过构造注入……让'什么被禁止'这一策略决定集中在一处"。因此黑名单以独立 Bean 存在，护栏在 L-B
   * 直接用它判定，而不是去改注册表的内部状态。
   *
   * <p><strong>为什么这里刻意不定义 {@code CapabilityRegistry} Bean</strong>（曾经踩过的坑，两处都是启动期硬失败）：
   *
   * <ol>
   *   <li><strong>Bean 定义重名</strong>：task-1 的 {@code AgentCapabilityAutoConfiguration#capabilityRegistry} 与护栏若都声明
   *       名为 {@code capabilityRegistry} 的 {@code @Bean}，Spring 默认禁止定义覆盖，容器直接抛 {@code
   *       BeanDefinitionOverrideException}。<em>{@code @ConditionalOnMissingBean} 管不了这件事</em>——它决定"要不要创建"，管不了
   *       "定义是否重名"。改名 + {@code @Primary} 可以绕过这一条。
   *   <li><strong>循环依赖</strong>（改名后立刻撞上）：护栏的注册表需要 {@code List<AgentCapability>} 才能合并全部能力来源，而
   *       端点层的 {@code invokeEndpointCapability}（本身就是 {@code List<AgentCapability>} 的一员）又需要 {@code
   *       CapabilityRegistry}。于是形成 {@code registry → List<AgentCapability> → invokeEndpointCapability → registry} 的闭环，
   *       容器抛 {@code BeanCurrentlyInCreationException}。
   * </ol>
   *
   * <p>结论：让 task-1 的默认注册表继续存在（它已经汇总了全部能力来源），护栏只额外持有黑名单。这样既没有重名、没有环，也不会
   * 让 13 个 {@code SecurityTool} 能力消失。装配正确性由 {@code CapabilityGateConfigurationTest} 在容器里断言。
   */
  @Bean
  public CapabilityBlacklist capabilityBlacklist(
      @Value("${toolbox.agent.guard.extra-blocked-codes:}") String extraBlockedCodes,
      @Value("${toolbox.agent.guard.extra-blocked-paths:}") String extraBlockedPaths) {
    return CapabilityBlacklist.defaults()
        .withAdditional(parseCodes(extraBlockedCodes), parseCodes(extraBlockedPaths));
  }

  /** 审计出口：接到平台既有 {@link AuditService}，全量记录（含被拒绝的调用）。 */
  @Bean
  public CapabilityAuditSink capabilityAuditSink(AuditService auditService) {
    return CapabilityAuditSink.of(auditService);
  }

  /**
   * 端点透传参数策略（§6.5 反向能力映射，防 X-7）。
   *
   * <p>把 {@code invoke_endpoint("POST", "/api/tasks", {parameters:{...}})} 的<strong>内层</strong>参数拉回能力治理：
   * 工具参数白名单、端口 ⊆ 授权端口、MSF 模块前缀、PoC 编号与数量、<strong>取值枚举（D-1..D-4）</strong>、
   * <strong>主机/URI 授权校验（D-5）</strong>。
   *
   * <p>外层 schema 校验看不出问题，危险在内容里。
   *
   * <p><strong>D-5 修复</strong>：注入 {@code TargetPolicyService}，使护栏侧也能执行
   * {@code validatedHttpUri}/{@code validatedHost}——没有它，经通用原语提交
   * {@code sqlmap_scan + path="http://169.254.169.254/..."} 会绕过云元数据 SSRF 防护。
   *
   * <p>取值规格与执行侧共用 {@code ToolParameterSpec}（单一事实来源），杜绝 D-1..D-4 类漂移。
   */
  @Bean
  public EndpointParameterPolicy endpointParameterPolicy(
      com.bachelor.toolbox.target.PortRangeParser portRangeParser,
      com.bachelor.toolbox.target.TargetPolicyService targetPolicyService,
      @Value("${toolbox.execution.max-ports-per-task:65535}") int maxPortsPerTask) {
    return new EndpointParameterPolicy(portRangeParser, maxPortsPerTask, targetPolicyService);
  }

  /**
   * 目标访问器。
   *
   * <p>复用 {@link TargetService#getCurrentlyAuthorized(Long)} 而不是直接读仓储：这样"目标是否存在、是否已停用、授权是否在有效期
   * 内、调用者是否有权访问"这些既有语义<strong>由同一个地方</strong>决定，护栏不重复实现（避免两套规则漂移），也无法被绕过。
   */
  @Bean
  public CapabilityGate.TargetAccessResolver capabilityTargetAccessResolver(TargetService targetService) {
    return targetId -> {
      try {
        AuthorizedTarget target = targetService.getCurrentlyAuthorized(targetId);
        return java.util.Optional.ofNullable(target);
      } catch (RuntimeException denied) {
        // 目标不存在 / 无权访问 / 已停用 / 授权过期 → 一律按"不可用"处理，由护栏 fail-closed 拒绝。
        return java.util.Optional.empty();
      }
    };
  }

  /** 审批访问器（§6.7 授权快照比对）。 */
  @Bean
  public CapabilityGate.ApprovalResolver capabilityApprovalResolver(
      com.bachelor.toolbox.project.ProjectApprovalRepository repository) {
    return CapabilityGate.ApprovalResolver.from(repository);
  }

  /**
   * 按需授权凭据解析器（"先看见，要用时申请"）。
   *
   * <p>这是护栏的<strong>第三个出口</strong>：未授权时返回 {@link CapabilityOutcome#approvalRequired}
   * 而不是拒绝，让 Agent 知道"可以申请"，从而在不放松安全的前提下用上全部能力。
   *
   * <p><strong>为什么需要它</strong>：护栏原先只有"已授权 → 放行"与"未授权 → 拒绝"两个出口。
   * 后果是 Agent 能看见 206 个能力，但只有 24 个核心能力可用——遇到未授权时只得到一句"拒绝"，
   * <strong>不知道可以申请</strong>，于是放弃或尝试绕过。
   *
   * <p><strong>安全设计</strong>：
   *
   * <ol>
   *   <li>凭据绑定四要素：能力 + 目标 + <strong>参数摘要</strong> + 时效。
   *       批准 {@code ports=80} 的凭据不能用于 {@code ports=3306}（防 TOCTOU）。
   *   <li>只有 {@code TARGET_NOT_FOUND}/{@code TARGET_DISABLED}/{@code AUTHORIZATION_EXPIRED}
   *       可转为申请；端口越界、绑定非法等<strong>真正越权仍直接拒绝</strong>（申请不是逃生门）。
   *   <li>默认粒度为 {@link ApprovalLevel#SINGLE}（一次性），<strong>绝不提供"全部允许"</strong>。
   *   <li>申请摘要由平台生成，不含 Agent 措辞（防"把 3306 说成 80"）。
   * </ol>
   *
   * <p>返回 {@link CapabilityApprovalGrantResolver#denyAll()}：<strong>凭据签发需要用户交互，
   * 属于 UI 层职责</strong>。本配置只提供"校验 + 拒绝"的默认实现——即未接入 UI 时
   * 行为退回"未授权即拒绝"，<strong>不会因为缺少实现而 fail-open</strong>。
   * UI 层应覆盖本 Bean 以接入真实的批准流程。
   */
  @Bean
  @org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean(
      CapabilityApprovalGrantResolver.class)
  public CapabilityApprovalGrantResolver capabilityApprovalGrantResolver() {
    return new InMemoryCapabilityApprovalGrantResolver();
  }

  /**
   * 待批申请登记表。
   *
   * <p>护栏返回"申请授权"时把申请登记在此，用户批准时服务端据此验证
   * "这条申请确实由 Agent 提出过"——<strong>防止凭空构造批准请求</strong>。
   *
   * <p>容量上限 {@value PendingApprovalRegistry#MAX_PENDING}，有效期
   * {@value PendingApprovalRegistry#PENDING_TTL_MINUTES} 分钟，防止 Agent
   * 反复申请把内存撑爆（拒绝服务）。
   */
  @Bean
  @org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean(
      PendingApprovalRegistry.class)
  public PendingApprovalRegistry capabilityPendingApprovalRegistry() {
    return new PendingApprovalRegistry();
  }

  /**
   * 当前调用主体解析器。
   *
   * <p>刻意<strong>不</strong>以 {@code Supplier<String>} 作为 Bean 类型：那是一个极其宽泛的类型，会与容器里任何其他
   * {@code Supplier} 注入点互相干扰。调用方需要主体时直接注入 {@link ProjectAuthorizationService} 即可。
   */
  public static String currentOperator(ProjectAuthorizationService authorization) {
    try {
      return authorization.currentUsername();
    } catch (RuntimeException anonymous) {
      return null;
    }
  }

  private static Set<String> parseCodes(String commaSeparated) {
    Set<String> codes = new java.util.TreeSet<>();
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
}
