package com.bachelor.toolbox.ai.guard;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * 第386轮：能力黑名单必须覆盖"清空全部业务数据"的端点。
 *
 * <p>黑名单自身声明「业务数据重置：不可逆破坏 → 绝对禁止」，但只登记了
 * {@code /api/settings/business-data*}、{@code /api/settings/reset}、{@code /api/settings/data-reset}，
 * **漏掉了实际存在的 `DELETE /api/settings/data`**（{@code SettingsController} → {@code BusinessDataResetService.clear}）。
 *
 * <p>后果：Agent 经通用原语 {@code invoke_endpoint("DELETE", "/api/settings/data")} 不会被
 * 「绝对禁止」拦住，只落在"需管理员逐次确认"这一层——与黑名单对同类不可逆操作的立场不一致（
 * 管理员可能被诱导点下确认）。
 *
 * <p>注意：黑名单按**路径**匹配、不区分 HTTP 方法，因此只能收录"该路径上所有方法都是破坏性"的端点；
 * {@code /api/findings}、{@code /api/vulnerabilities/catalog} 同时提供读接口，**不**纳入（否则会阻断合法读取）。
 */
@DisplayName("能力黑名单覆盖破坏性清空端点（第386轮）")
class GuardBlacklistDestructiveEndpointsTests {

  private final CapabilityBlacklist blacklist = CapabilityBlacklist.defaults();

  @Test
  @DisplayName("DELETE /api/settings/data（清空全部业务数据）必须在绝对禁止名单内")
  void clearAllBusinessDataIsAbsolutelyForbidden() {
    assertThat(blacklist.blocksPath("/api/settings/data"))
        .as("清空全部业务数据的端点必须被绝对禁止")
        .isTrue();
  }

  @Test
  @DisplayName("既有破坏性端点仍然被禁止（防回归）")
  void existingDestructiveEndpointsStayBlocked() {
    assertThat(blacklist.blocksPath("/api/system/shutdown")).isTrue();
    assertThat(blacklist.blocksPath("/api/settings/business-data")).isTrue();
    assertThat(blacklist.blocksPath("/api/settings/reset")).isTrue();
    assertThat(blacklist.blocksPath("/api/auth/login")).isTrue();
  }

  @Test
  @DisplayName("合法读取路径不得被误伤（黑名单按路径匹配，不能过宽）")
  void ordinaryReadPathsAreNotBlocked() {
    assertThat(blacklist.blocksPath("/api/findings")).isFalse();
    assertThat(blacklist.blocksPath("/api/vulnerabilities/catalog")).isFalse();
    assertThat(blacklist.blocksPath("/api/tasks")).isFalse();
    assertThat(blacklist.blocksPath("/api/settings")).isFalse();
  }
}
