package com.bachelor.toolbox.ai.guard;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.bachelor.toolbox.ai.capability.AgentCapability;
import com.bachelor.toolbox.ai.capability.CapabilityRegistry;
import com.bachelor.toolbox.tool.SecurityTool;
import com.bachelor.toolbox.tool.SecurityToolRegistry;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;

/**
 * 护栏装配测试（容器级）。
 *
 * <p>存在的理由来自 task-1 的实测教训：Spring 装配错误（{@code @Component} + {@code @Bean} 重复定义导致上下文启动失败）
 * <strong>单元测试全绿也抓不到</strong>，只有起容器才暴露。
 *
 * <p>本测试重点验证一件事：护栏定义的 {@link CapabilityRegistry} Bean 是"<strong>合并</strong>"而不是"覆盖"。若写错，13 个
 * {@code SecurityTool} 能力会从注册表消失，护栏随即变成"拒绝一切"——而且是静默发生的。
 */
@SpringBootTest(
    properties = {
      "spring.datasource.url=jdbc:h2:mem:guard-test;MODE=PostgreSQL;DB_CLOSE_DELAY=-1",
      "spring.jpa.hibernate.ddl-auto=create-drop",
      "toolbox.ai.api-key=",
      "toolbox.ai.enabled=false",
      "toolbox.auth.admin-password=test-admin-password-7bbbe095d8724fcb",
      "toolbox.auth.jwt-secret=test-jwt-secret-cdc24d415ad843aa9ef313028ae9be30",
      "toolbox.traffic.mitm-ca-password=test-mitm-ca-password-1d6ad9b95b76490e",
      "toolbox.traffic.mitm-enabled=false",
      "toolbox.vulnerability-catalog.nuclei.import-on-startup=false",
      "toolbox.vulnerability-catalog.scanner-pocs.import-on-startup=false"
    })
class CapabilityGateConfigurationTest {

  @Autowired private CapabilityGate capabilityGate;
  @Autowired private CapabilityRegistry capabilityRegistry;
  @Autowired private SecurityToolRegistry securityToolRegistry;
  @Autowired private CapabilityBlacklist capabilityBlacklist;
  @Autowired private CapabilityGate.TargetAccessResolver targetAccessResolver;
  @Autowired private CapabilityAuditSink capabilityAuditSink;
  @Autowired private ApplicationContext applicationContext;

  /** 护栏本身能装配起来，且依赖齐全。 */
  @Test
  void guardIsWiredWithAllCollaborators() {
    assertNotNull(capabilityGate);
    assertNotNull(capabilityBlacklist);
    assertNotNull(targetAccessResolver);
    assertNotNull(capabilityAuditSink);
    assertFalse(
        capabilityAuditSink == CapabilityAuditSink.NOOP,
        "生产装配必须接上真实审计，而不是丢弃审计的 NOOP 实现");
  }

  /**
   * 合并而非覆盖：注册表必须包含全部 {@link SecurityTool} 能力。
   *
   * <p>这是 task-1 警告的那个坑：护栏若整体替换默认注册表 Bean，能力会消失。
   *
   * <p><strong>断言写成"包含"而不是"数量相等"</strong>：注册表同时汇总了端点派生能力（路线 B，约 168 个）与通用端点原语，
   * 总数必然<em>大于</em> {@link SecurityTool} 数量。早期版本这里写的是"两者数量相等"，在端点派生能力接入后变成过时假设而失败
   * （{@code expected: <14> but was: <182>}）——那个失败本身恰好证明了"护栏没有替换默认 Bean"，只是断言形式错了。
   *
   * <p>刻意<strong>不</strong>硬编码 {@code 182}：端点数量由运行期 MVC 扫描决定，硬编码会让本测试在任何控制器增删时失败
   * （脆性断言）。核心意图是"SecurityTool 能力一个都不能丢"，用 {@code >=} + 逐个 {@code find()} 存在性检查即可锁定，
   * 且不与端点数量耦合。
   */
  @Test
  void registryMergesEverySecurityToolCapabilityInsteadOfReplacingThem() {
    assertTrue(securityToolRegistry.all().size() > 0, "至少应有一个安全工具");

    assertTrue(
        capabilityRegistry.size() >= securityToolRegistry.all().size(),
        "护栏定义的注册表必须汇总全部能力来源，不能整体替换默认 Bean（实际 "
            + capabilityRegistry.size()
            + "，SecurityTool 数 "
            + securityToolRegistry.all().size()
            + "）");

    for (SecurityTool tool : securityToolRegistry.all()) {
      assertTrue(
          capabilityRegistry.find(tool.code()).isPresent(),
          "能力 " + tool.code() + " 必须仍在注册表中（否则护栏会拒绝一切）");
    }
  }

  /**
   * 黑名单的策略来源是护栏自己的 {@link CapabilityBlacklist} Bean，<strong>不是</strong>注册表的内部状态。
   *
   * <p>这是刻意的架构选择（见 {@code AgentCapabilityGuardConfiguration} 的注释）：护栏不重新定义 {@code
   * CapabilityRegistry} Bean，否则会撞上"Bean 定义重名"与"循环依赖"两处启动期硬失败。因此 task-1 的注册表黑名单为空，
   * 而 L-B 判定走的是护栏持有的黑名单——本测试锁住这个契约，防止有人误以为"注册表黑名单为空 = 护栏失效"。
   */
  @Test
  void blacklistIsOwnedByTheGuardNotTheRegistry() {
    assertFalse(
        capabilityBlacklist.blockedCodes().isEmpty(), "护栏黑名单必须有内容（§6.4 默认表）");
    assertTrue(
        capabilityRegistry.blockedCodes().isEmpty(),
        "注册表黑名单应为空：护栏通过独立 Bean 判定黑名单，不修改注册表内部状态");
    // 真正的契约：被禁止的能力必须由护栏拦下，而不是靠注册表。
    assertTrue(capabilityBlacklist.blocksCode("shutdown_system"));
  }

  /** 黑名单配置包含 §6.4 表格里的全部三类端点。 */
  @Test
  void blacklistCoversAllSection64Categories() {
    assertTrue(capabilityBlacklist.blocksPath("/api/system/shutdown"), "系统关机");
    assertTrue(capabilityBlacklist.blocksPath("/api/auth/login"), "/api/auth/* 前缀");
    assertTrue(capabilityBlacklist.blocksPath("/api/auth/change-password"), "修改密码");
    assertTrue(capabilityBlacklist.blocksCode("reset_business_data"), "业务数据重置");
    assertTrue(capabilityBlacklist.blocksCode("manage_users"), "用户/权限管理");
  }

  /** 默认 schema 模式必须是 WARN（§4.1.1 的 targetId required 会误拦现有 13 条执行链路）。 */
  @Test
  void schemaModeDefaultsToWarnToAvoidFalseBlocks() {
    assertEquals(
        CapabilityGate.SchemaMode.WARN,
        capabilityGate.schemaMode(),
        "默认必须为 WARN；§9.5 对照实验需显式配置 toolbox.agent.guard.schema-mode=enforce");
  }

  /** 白名单默认不开启任何高危能力（fail-closed）。 */
  @Test
  void whitelistIsEmptyByDefault() {
    assertTrue(capabilityGate.enabledWhitelist().isEmpty(), "白名单默认必须为空（未开启 → 拒绝）");
  }

  /** 真实安全工具能力在护栏下确实可被校验（拿真实能力跑一遍，验证接口契约没漂移）。 */
  @Test
  void realSecurityToolCapabilityIsGuarded() {
    AgentCapability nuclei = capabilityRegistry.require("nuclei_scan");

    // 未带 targetId → 哨兵态，护栏必须拒绝（而不是当成"不触及目标"放行）。
    assertTrue(
        nuclei.targetBindings(java.util.Map.of()).contains(AgentCapability.TARGET_BINDING_UNRESOLVED),
        "真实扫描能力缺目标时必须返回哨兵");

    CapabilityDeniedException error =
        org.junit.jupiter.api.Assertions.assertThrows(
            CapabilityDeniedException.class,
            () ->
                capabilityGate.invoke(
                    "nuclei_scan",
                    java.util.Map.of(),
                    CapabilityContext.anonymous().approved(1L)));
    assertNotNull(error.reasonCode());
  }

  /** 未知能力（§6.5 未注册端点）一律拒绝。 */
  @Test
  void unregisteredCapabilityIsDenied() {
    CapabilityDeniedException error =
        org.junit.jupiter.api.Assertions.assertThrows(
            CapabilityDeniedException.class,
            () -> capabilityGate.invoke("no_such_capability", java.util.Map.of(), CapabilityContext.anonymous()));
    assertEquals(CapabilityDeniedException.Layer.ENTRYPOINT, error.layer());
    assertEquals("UNKNOWN_CAPABILITY", error.reasonCode());
  }

  /** 黑名单 Bean 是单例，护栏与配置拿到的是同一个实例（避免两套黑名单漂移）。 */
  @Test
  void blacklistBeanIsShared() {
    assertSame(capabilityBlacklist, applicationContext.getBean(CapabilityBlacklist.class));
    assertSame(capabilityGate.blacklist(), capabilityBlacklist);
  }

  /** 护栏 Bean 的唯一性：容器里不能出现第二个 CapabilityGate（否则存在旁路）。 */
  @Test
  void thereIsExactlyOneCapabilityGate() {
    assertEquals(1, applicationContext.getBeansOfType(CapabilityGate.class).size());
  }

  /** 全部能力都应能被护栏查询到（无"注册了但查不到"的静默丢失）。 */
  @Test
  void everyRegisteredCapabilityIsResolvableByTheGate() {
    List<String> missing =
        capabilityRegistry.all().stream()
            .map(AgentCapability::code)
            .filter(code -> !capabilityGate.isRegistered(code))
            .toList();
    assertEquals(List.of(), missing, "存在注册了但护栏查不到的能力: " + missing);
  }

  /** 黑名单能力码集合不为空，且与 §6.4 表格一致。 */
  @Test
  void blacklistCodeSnapshotIsNotEmpty() {
    Set<String> codes = capabilityBlacklist.blockedCodes();
    assertFalse(codes.isEmpty());
    assertTrue(codes.contains("shutdown_system"));
    assertTrue(codes.contains("change_password"));
  }

  // ==================================================================
  // 按需授权（"先看见，要用时申请"）的容器级装配验证
  // ==================================================================

  @Autowired private CapabilityApprovalGrantResolver capabilityApprovalGrantResolver;
  @Autowired private PendingApprovalRegistry pendingApprovalRegistry;

  /**
   * 按需授权的两个 Bean 必须在容器里真实存在。
   *
   * <p>为什么需要容器级验证：这两个 Bean 都是护栏构造器的<strong>可选依赖</strong>
   * （{@code required = false}）。若装配漏了，{@code CapabilityGate} 照样能创建，
   * <strong>所有单元测试也全绿</strong>——但"未授权 → 申请"这个出口会静默退化为
   * "未授权 → 直接拒绝"，Agent 又回到"能看见却用不了"的状态。
   *
   * <p>这正是本类存在的理由（task-1 的教训）：<strong>Spring 装配错误只有起容器才暴露</strong>。
   */
  @Test
  void onDemandApprovalBeansAreWired() {
    assertNotNull(
        capabilityApprovalGrantResolver,
        "按需授权凭据解析器必须装配，否则护栏的第三个出口退化为直接拒绝");
    assertNotNull(
        pendingApprovalRegistry, "待批申请登记表必须装配，否则用户批准时无法验证申请真实存在");
  }

  /**
   * 凭据解析器必须注入到 {@code CapabilityGate} 内部（而不是仅仅存在于容器里）。
   *
   * <p>区别于上一条：Bean 存在 ≠ 被用上。护栏构造器有三级重载，若 {@code @Bean} 方法
   * 或构造器委托写错，可能出现"Bean 在容器里，但 gate 拿到的是 null"。
   */
  @Test
  void capabilityGateActuallyReceivedTheApprovalResolver() {
    assertTrue(
        capabilityGate.hasOnDemandApproval(),
        "护栏必须真的持有按需授权解析器——否则未授权目标会被直接拒绝，"
            + "Agent 无法通过'申请'获得授权（Bean 存在但没接上）");
  }

  /** 登记表是单例：护栏登记的申请必须能被批准端点查到（同一实例）。 */
  @Test
  void pendingRegistryIsSharedBetweenGateAndApprovalEndpoint() {
    assertEquals(
        1,
        applicationContext.getBeansOfType(PendingApprovalRegistry.class).size(),
        "登记表必须是单例——多实例会导致'护栏登记到 A，批准端点查 B'而永远查不到");
  }
}
