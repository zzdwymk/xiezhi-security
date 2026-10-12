package com.bachelor.toolbox.ai.guard;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;

/**
 * <strong>按需授权基础设施的对抗验证</strong>：待批登记表 + 批准端点 + 凭据存储。
 *
 * <h2>为什么这三样也要对抗验证</h2>
 *
 * <p>{@link GuardOnDemandApprovalTests} 验证的是"护栏会提出申请"，但申请提出来之后
 * 还需要"用户能批准"的通道。这条通道本身是<strong>新的攻击面</strong>：
 *
 * <ol>
 *   <li><strong>凭空批准</strong>：攻击者不经过 Agent 直接调批准端点，能否签发凭据？
 *   <li><strong>批准 A 执行 B</strong>：凭据是否真正绑定四要素？
 *   <li><strong>重放</strong>：一次性凭据能否被用第二次？
 *   <li><strong>拒绝服务</strong>：Agent 反复申请能否把内存撑爆？
 *   <li><strong>Agent 自我批准</strong>：Agent 能否调用批准端点给自己授权？
 * </ol>
 */
@DisplayName("按需授权基础设施：登记表 / 批准端点 / 凭据存储")
class GuardApprovalInfrastructureTests {

  private static CapabilityApprovalRequest request(String code, String target, Map<String, Object> params) {
    return new CapabilityApprovalRequest(
        code,
        target,
        CapabilityApprovalRequest.digestOf(code, target, params),
        "SENSITIVE",
        ApprovalLevel.SINGLE,
        "平台生成的摘要",
        params);
  }

  // ==================================================================
  // A. 待批登记表
  // ==================================================================

  @Nested
  @DisplayName("A. 待批申请登记表")
  class Registry {

    @Test
    @DisplayName("A-1 登记后可按四要素查到")
    void registeredRequestIsFindable() {
      PendingApprovalRegistry registry = new PendingApprovalRegistry();
      CapabilityApprovalRequest req = request("scan_a", "2", Map.of("ports", "80"));

      registry.register(req);

      Optional<CapabilityApprovalRequest> found =
          registry.find("scan_a", "2", req.parameterDigest());
      Assertions.assertTrue(found.isPresent(), "登记后应能查到");
      Assertions.assertEquals("scan_a", found.get().capabilityCode());
    }

    @Test
    @DisplayName("A-2 未登记的申请查不到（防凭空批准）")
    void unregisteredRequestIsNotFound() {
      PendingApprovalRegistry registry = new PendingApprovalRegistry();

      Assertions.assertTrue(
          registry.find("never_requested", "99", "fake-digest").isEmpty(),
          "没有对应待批申请的批准必须查不到——这是防止凭空构造批准的关键");
    }

    @Test
    @DisplayName("A-3 四要素任一不符即查不到（防批准 A 执行 B）")
    void lookupRequiresAllFourElements() {
      PendingApprovalRegistry registry = new PendingApprovalRegistry();
      CapabilityApprovalRequest req = request("scan_b", "2", Map.of("ports", "80"));
      registry.register(req);

      Assertions.assertTrue(registry.find("scan_OTHER", "2", req.parameterDigest()).isEmpty());
      Assertions.assertTrue(registry.find("scan_b", "9", req.parameterDigest()).isEmpty());
      Assertions.assertTrue(registry.find("scan_b", "2", "other-digest").isEmpty());
      Assertions.assertTrue(registry.find("scan_b", "2", req.parameterDigest()).isPresent());
    }

    @Test
    @DisplayName("A-4 批准后移除，防止重复批准")
    void removeAfterGrant() {
      PendingApprovalRegistry registry = new PendingApprovalRegistry();
      CapabilityApprovalRequest req = request("scan_c", "2", Map.of());
      registry.register(req);

      registry.remove("scan_c", "2", req.parameterDigest());

      Assertions.assertTrue(registry.find("scan_c", "2", req.parameterDigest()).isEmpty());
    }

    @Test
    @DisplayName("A-5 重复登记同一申请只保留一条（防刷屏）")
    void duplicateRegistrationIsDeduplicated() {
      PendingApprovalRegistry registry = new PendingApprovalRegistry();
      CapabilityApprovalRequest req = request("scan_d", "2", Map.of("ports", "80"));

      registry.register(req);
      registry.register(req);
      registry.register(req);

      Assertions.assertEquals(1, registry.size(), "同一申请重复提出只应保留一条");
    }

    @Test
    @DisplayName("A-6 容量上限：超出时丢弃最旧的（防拒绝服务）")
    void capacityLimitEvictsOldest() {
      PendingApprovalRegistry registry = new PendingApprovalRegistry();
      int overflow = PendingApprovalRegistry.MAX_PENDING + 20;
      for (int index = 0; index < overflow; index++) {
        registry.register(request("scan_" + index, String.valueOf(index), Map.of()));
      }

      Assertions.assertTrue(
          registry.size() <= PendingApprovalRegistry.MAX_PENDING,
          "待批数量必须受容量上限约束，否则 Agent 反复申请可撑爆内存；实际 "
              + registry.size()
              + " 上限 "
              + PendingApprovalRegistry.MAX_PENDING);
    }
  }

  // ==================================================================
  // B. 凭据存储
  // ==================================================================

  @Nested
  @DisplayName("B. 凭据存储（InMemory）")
  class GrantStore {

    @Test
    @DisplayName("B-1 签发后可校验通过（完整闭环）")
    void grantedApprovalIsValid() {
      InMemoryCapabilityApprovalGrantResolver resolver = new InMemoryCapabilityApprovalGrantResolver();
      CapabilityApprovalRequest req = request("scan_e", "2", Map.of("ports", "80"));

      resolver.grant(req, ApprovalLevel.SESSION);

      Assertions.assertTrue(
          resolver.hasValidApproval("scan_e", "2", req.parameterDigest()), "签发后应校验通过");
    }

    @Test
    @DisplayName("B-2 未签发 → 校验不通过")
    void ungrantedApprovalIsInvalid() {
      InMemoryCapabilityApprovalGrantResolver resolver = new InMemoryCapabilityApprovalGrantResolver();

      Assertions.assertFalse(
          resolver.hasValidApproval("scan_f", "2", "digest"), "未签发不得通过校验");
    }

    @Test
    @DisplayName("B-3 SINGLE 是一次性：用后即焚（防重放）")
    void singleLevelGrantIsConsumedOnce() {
      InMemoryCapabilityApprovalGrantResolver resolver = new InMemoryCapabilityApprovalGrantResolver();
      CapabilityApprovalRequest req = request("scan_g", "2", Map.of("ports", "80"));
      resolver.grant(req, ApprovalLevel.SINGLE);

      Assertions.assertTrue(
          resolver.hasValidApproval("scan_g", "2", req.parameterDigest()), "第一次应通过");
      Assertions.assertFalse(
          resolver.hasValidApproval("scan_g", "2", req.parameterDigest()),
          "一次性凭据第二次必须失效（防重放）");
    }

    @Test
    @DisplayName("B-4 SESSION 级在有效期内可重复使用")
    void sessionLevelGrantIsReusable() {
      InMemoryCapabilityApprovalGrantResolver resolver = new InMemoryCapabilityApprovalGrantResolver();
      CapabilityApprovalRequest req = request("scan_h", "2", Map.of("ports", "80"));
      resolver.grant(req, ApprovalLevel.SESSION);

      Assertions.assertTrue(resolver.hasValidApproval("scan_h", "2", req.parameterDigest()));
      Assertions.assertTrue(
          resolver.hasValidApproval("scan_h", "2", req.parameterDigest()),
          "会话级凭据在有效期内应可重复使用");
    }

    @Test
    @DisplayName("B-5 凭据不跨目标/跨参数复用")
    void grantIsNotCrossApplicable() {
      InMemoryCapabilityApprovalGrantResolver resolver = new InMemoryCapabilityApprovalGrantResolver();
      CapabilityApprovalRequest req = request("scan_i", "2", Map.of("ports", "80"));
      resolver.grant(req, ApprovalLevel.SESSION);

      Assertions.assertFalse(
          resolver.hasValidApproval("scan_i", "9", req.parameterDigest()), "不得跨目标复用");
      Assertions.assertFalse(
          resolver.hasValidApproval(
              "scan_i", "2", CapabilityApprovalRequest.digestOf("scan_i", "2", Map.of("ports", "3306"))),
          "不得跨参数复用（防 TOCTOU）");
    }

    @Test
    @DisplayName("B-6 撤销后立即失效")
    void revokeInvalidatesGrant() {
      InMemoryCapabilityApprovalGrantResolver resolver = new InMemoryCapabilityApprovalGrantResolver();
      CapabilityApprovalRequest req = request("scan_j", "2", Map.of());
      resolver.grant(req, ApprovalLevel.SESSION);

      Assertions.assertTrue(resolver.revoke("scan_j", "2", req.parameterDigest()));
      Assertions.assertFalse(
          resolver.hasValidApproval("scan_j", "2", req.parameterDigest()), "撤销后必须立即失效");
    }

    @Test
    @DisplayName("B-7 FORBIDDEN 级拒绝签发")
    void forbiddenLevelCannotBeGranted() {
      InMemoryCapabilityApprovalGrantResolver resolver = new InMemoryCapabilityApprovalGrantResolver();

      Assertions.assertThrows(
          IllegalArgumentException.class,
          () -> resolver.grant(request("scan_k", "2", Map.of()), ApprovalLevel.FORBIDDEN),
          "禁止的能力不得签发凭据");
    }

    @Test
    @DisplayName("B-8 denyAll 实现拒绝一切（未装配时 fail-closed）")
    void denyAllRejectsEverything() {
      CapabilityApprovalGrantResolver denyAll = CapabilityApprovalGrantResolver.denyAll();

      Assertions.assertFalse(denyAll.hasValidApproval("any", "1", "any"));
    }
  }

  // ==================================================================
  // C. 批准端点
  // ==================================================================

  @Nested
  @DisplayName("C. 批准端点（防凭空批准 / 防 Agent 自我批准）")
  class Controller {

    private CapabilityApprovalController controller(
        InMemoryCapabilityApprovalGrantResolver resolver, PendingApprovalRegistry registry) {
      return new CapabilityApprovalController(resolver, registry);
    }

    @Test
    @DisplayName("C-1 有对应待批申请 → 批准成功并签发凭据")
    void grantSucceedsForPendingRequest() {
      InMemoryCapabilityApprovalGrantResolver resolver = new InMemoryCapabilityApprovalGrantResolver();
      PendingApprovalRegistry registry = new PendingApprovalRegistry();
      CapabilityApprovalRequest req = request("scan_l", "2", Map.of("ports", "80"));
      registry.register(req);

      ResponseEntity<Map<String, Object>> response =
          controller(resolver, registry)
              .grant(
                  new CapabilityApprovalController.GrantRequest(
                      "scan_l", "2", req.parameterDigest(), ApprovalLevel.SESSION));

      Assertions.assertEquals(200, response.getStatusCode().value());
      Assertions.assertTrue(
          resolver.hasValidApproval("scan_l", "2", req.parameterDigest()),
          "批准后必须真的签发凭据（否则链路断开）");
    }

    @Test
    @DisplayName("C-2 没有对应待批申请 → 拒绝签发（防凭空批准）")
    void grantFailsWithoutPendingRequest() {
      InMemoryCapabilityApprovalGrantResolver resolver = new InMemoryCapabilityApprovalGrantResolver();
      PendingApprovalRegistry registry = new PendingApprovalRegistry();

      ResponseEntity<Map<String, Object>> response =
          controller(resolver, registry)
              .grant(
                  new CapabilityApprovalController.GrantRequest(
                      "never_requested", "99", "forged-digest", ApprovalLevel.SESSION));

      Assertions.assertEquals(400, response.getStatusCode().value(), "凭空批准必须被拒绝");
      Assertions.assertFalse(
          resolver.hasValidApproval("never_requested", "99", "forged-digest"),
          "被拒绝的批准不得签发任何凭据");
    }

    @Test
    @DisplayName("C-3 批准后待批申请被移除（防重复批准）")
    void pendingRemovedAfterGrant() {
      InMemoryCapabilityApprovalGrantResolver resolver = new InMemoryCapabilityApprovalGrantResolver();
      PendingApprovalRegistry registry = new PendingApprovalRegistry();
      CapabilityApprovalRequest req = request("scan_m", "2", Map.of());
      registry.register(req);

      controller(resolver, registry)
          .grant(new CapabilityApprovalController.GrantRequest("scan_m", "2", req.parameterDigest(), null));

      Assertions.assertTrue(
          registry.find("scan_m", "2", req.parameterDigest()).isEmpty(), "批准后应移除待批申请");
    }

    @Test
    @DisplayName("C-4 FORBIDDEN 级经端点批准也被拒")
    void forbiddenLevelRejectedViaEndpoint() {
      InMemoryCapabilityApprovalGrantResolver resolver = new InMemoryCapabilityApprovalGrantResolver();
      PendingApprovalRegistry registry = new PendingApprovalRegistry();
      CapabilityApprovalRequest req = request("scan_n", "2", Map.of());
      registry.register(req);

      ResponseEntity<Map<String, Object>> response =
          controller(resolver, registry)
              .grant(
                  new CapabilityApprovalController.GrantRequest(
                      "scan_n", "2", req.parameterDigest(), ApprovalLevel.FORBIDDEN));

      Assertions.assertEquals(400, response.getStatusCode().value());
    }

    @Test
    @DisplayName("C-5 缺少能力码/摘要 → 拒绝")
    void malformedGrantRejected() {
      InMemoryCapabilityApprovalGrantResolver resolver = new InMemoryCapabilityApprovalGrantResolver();
      PendingApprovalRegistry registry = new PendingApprovalRegistry();

      Assertions.assertEquals(
          400,
          controller(resolver, registry)
              .grant(new CapabilityApprovalController.GrantRequest(null, "2", "d", null))
              .getStatusCode()
              .value());
      Assertions.assertEquals(
          400,
          controller(resolver, registry)
              .grant(new CapabilityApprovalController.GrantRequest("scan_o", "2", null, null))
              .getStatusCode()
              .value());
    }

    @Test
    @DisplayName("C-6 待批列表只含平台生成字段（不含 Agent 自由文本）")
    void pendingListExposesPlatformFieldsOnly() {
      InMemoryCapabilityApprovalGrantResolver resolver = new InMemoryCapabilityApprovalGrantResolver();
      PendingApprovalRegistry registry = new PendingApprovalRegistry();
      registry.register(request("scan_p", "2", Map.of("ports", "80")));

      List<Map<String, Object>> pending = controller(resolver, registry).pending();

      Assertions.assertEquals(1, pending.size());
      Map<String, Object> card = pending.get(0);
      Assertions.assertEquals("scan_p", card.get("capabilityCode"));
      Assertions.assertEquals("2", card.get("targetId"));
      Assertions.assertNotNull(card.get("parameterDigest"), "卡片必须含参数摘要（用户据此核对）");
      Assertions.assertNotNull(card.get("summary"), "卡片必须含平台生成的摘要");
      Assertions.assertNotNull(card.get("parameters"), "卡片必须含参数原文（用户据此核对）");
    }

    @Test
    @DisplayName("C-7 撤销端点：撤销后凭据立即失效")
    void revokeEndpointWorks() {
      InMemoryCapabilityApprovalGrantResolver resolver = new InMemoryCapabilityApprovalGrantResolver();
      PendingApprovalRegistry registry = new PendingApprovalRegistry();
      CapabilityApprovalRequest req = request("scan_q", "2", Map.of());
      resolver.grant(req, ApprovalLevel.SESSION);

      controller(resolver, registry)
          .revoke(new CapabilityApprovalController.GrantRequest("scan_q", "2", req.parameterDigest(), null));

      Assertions.assertFalse(resolver.hasValidApproval("scan_q", "2", req.parameterDigest()));
    }
  }
}
