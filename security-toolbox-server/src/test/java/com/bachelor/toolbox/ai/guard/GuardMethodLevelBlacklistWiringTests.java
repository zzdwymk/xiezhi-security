package com.bachelor.toolbox.ai.guard;

import static com.bachelor.toolbox.ai.guard.GuardSupport.params;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.bachelor.toolbox.ai.capability.CapabilityRegistry;
import com.bachelor.toolbox.ai.endpoint.EndpointCapability;
import com.bachelor.toolbox.ai.endpoint.EndpointRegistry;
import com.bachelor.toolbox.ai.endpoint.InvokeEndpointCapability;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * 第387轮：方法级黑名单必须真的在调用链上（护栏接线，而非只验规则表）。
 *
 * <p>规则表层面的断言只能证明"表里有这条"，不能证明"调用链会用它"。本测试经完整
 * {@code gate.invoke("invoke_endpoint", …)} 验证：
 *
 * <ul>
 *   <li>{@code DELETE /api/findings}（批量删除全部发现）→ 在 ADMISSION 层以 {@code BLOCKED_CAPABILITY} 拒绝；
 *   <li>{@code GET /api/findings}（读取发现）→ 不被黑名单拦截（否则会把合法只读能力一起禁掉）。
 * </ul>
 */
@DisplayName("方法级黑名单接线（第387轮）")
class GuardMethodLevelBlacklistWiringTests {

  private static final Map<Long, com.bachelor.toolbox.target.AuthorizedTarget> TARGETS =
      Map.of(1L, GuardSupport.target(1L, "http://192.168.222.155/", "80"));

  private GuardSupport.Fixture fixture() {
    EndpointRegistry endpointRegistry = new EndpointRegistry();
    EndpointCapability deleteFinding = EndpointCapability.derive("DELETE", "/api/findings", "删除全部发现");
    EndpointCapability getFinding = EndpointCapability.derive("GET", "/api/findings", "查询发现");
    endpointRegistry.register(deleteFinding);
    endpointRegistry.register(getFinding);
    InvokeEndpointCapability invoke =
        new InvokeEndpointCapability(endpointRegistry, new CapabilityRegistry(List.of()));
    return GuardSupport.fixture(
        List.of(invoke, deleteFinding, getFinding),
        TARGETS,
        CapabilityBlacklist.defaults(),
        InvokeEndpointCapability.CODE,
        InvokeEndpointCapability.CODE,
        CapabilityGate.SchemaMode.WARN,
        true);
  }

  private static CapabilityContext approved() {
    return CapabilityContext.of("ai-agent", 7L).approved(1L);
  }

  @Test
  @DisplayName("DELETE /api/findings 经 invoke_endpoint 被 ADMISSION 层绝对拒绝")
  void deleteAllFindingsIsDeniedAtAdmission() {
    GuardSupport.Fixture fixture = fixture();
    assertThatThrownBy(
            () ->
                fixture
                    .gate()
                    .invoke(
                        InvokeEndpointCapability.CODE,
                        params("method", "DELETE", "path", "/api/findings"),
                        approved()))
        .isInstanceOf(CapabilityDeniedException.class)
        .satisfies(
            error -> {
              CapabilityDeniedException denied = (CapabilityDeniedException) error;
              assertThat(denied.layer()).isEqualTo(CapabilityDeniedException.Layer.ADMISSION);
              assertThat(denied.reasonCode()).isEqualTo("BLOCKED_CAPABILITY");
            });
  }

  @Test
  @DisplayName("GET /api/findings 不被黑名单拦截（读方法必须放行）")
  void readFindingsIsNotBlockedByBlacklist() {
    GuardSupport.Fixture fixture = fixture();
    Throwable thrown =
        org.assertj.core.api.Assertions.catchThrowable(
            () ->
                fixture
                    .gate()
                    .invoke(
                        InvokeEndpointCapability.CODE,
                        params("method", "GET", "path", "/api/findings"),
                        approved()));
    // 读操作可能因其他治理层被拒（例如无目标绑定时的 L-A fail-closed），
    // 但**绝不能**是黑名单拒绝——那才说明规则过宽、误伤了合法只读能力。
    if (thrown instanceof CapabilityDeniedException denied) {
      assertThat(denied.reasonCode())
          .as("读方法不得被黑名单拦截")
          .isNotEqualTo("BLOCKED_CAPABILITY");
    }
    assertThat(blacklistBlocksGetFindings()).isFalse();
  }

  /** 直接验证规则层：GET /api/findings 不命中任何黑名单规则。 */
  private boolean blacklistBlocksGetFindings() {
    return CapabilityBlacklist.defaults().blocksMethodPath("GET", "/api/findings");
  }

  @Test
  @DisplayName("方法缺失时只按路径规则判定：DELETE /api/findings 不带 method 不会误放行路径级规则")
  void missingMethodDoesNotEscapePathLevelRules() {
    GuardSupport.Fixture fixture = fixture();
    assertThatThrownBy(
            () ->
                fixture
                    .gate()
                    .invoke(
                        InvokeEndpointCapability.CODE,
                        params("path", "/api/system/shutdown"),
                        approved()))
        .isInstanceOf(CapabilityDeniedException.class)
        .satisfies(
            error ->
                assertThat(((CapabilityDeniedException) error).reasonCode())
                    .isEqualTo("BLOCKED_CAPABILITY"));
  }
}
