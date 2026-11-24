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

  @Test
  @DisplayName("第388轮：清空全部抓包证据按「方法+路径」绝对禁止，单条删除与读取不受影响")
  void clearAllCapturedTrafficIsBlocked() {
    assertThat(blacklist.blocksMethodPath("DELETE", "/api/traffic/sessions"))
        .as("清空全部抓包证据必须绝对禁止")
        .isTrue();
    assertThat(blacklist.blocksMethodPath("GET", "/api/traffic/sessions"))
        .as("读取抓包会话必须放行")
        .isFalse();
    assertThat(blacklist.blocksMethodPath("DELETE", "/api/traffic/sessions/42"))
        .as("单条报文删除属正常清理，不得被禁")
        .isFalse();
    assertThat(blacklist.blocksMethodPath("DELETE", "/api/traffic/filters/9"))
        .as("删除过滤器不得被禁")
        .isFalse();
  }

  @Test
  @DisplayName("第387轮：批量删除类端点按「方法+路径」绝对禁止，读方法不受影响")
  void methodLevelDestructiveEndpointsAreBlocked() {
    assertThat(blacklist.blocksMethodPath("DELETE", "/api/findings"))
        .as("批量删除全部扫描发现必须绝对禁止")
        .isTrue();
    assertThat(blacklist.blocksMethodPath("delete", "/api/findings"))
        .as("方法名大小写不敏感")
        .isTrue();
    assertThat(blacklist.blocksMethodPath("GET", "/api/findings"))
        .as("读取发现必须放行")
        .isFalse();
    assertThat(blacklist.blocksMethodPath("DELETE", "/api/vulnerabilities/catalog"))
        .as("清空漏洞目录必须绝对禁止")
        .isTrue();
    assertThat(blacklist.blocksMethodPath("GET", "/api/vulnerabilities/catalog"))
        .as("读取漏洞目录必须放行")
        .isFalse();
  }

  @Test
  @DisplayName("第387轮：仅路径规则对所有方法生效（方法缺失也不能逃逸）")
  void pathOnlyRulesApplyToEveryMethod() {
    assertThat(blacklist.blocksMethodPath("GET", "/api/system/shutdown")).isTrue();
    assertThat(blacklist.blocksMethodPath(null, "/api/system/shutdown")).isTrue();
    assertThat(blacklist.blocksMethodPath("POST", "/api/settings/data")).isTrue();
    assertThat(blacklist.blocksMethodPath(null, "/api/settings/data")).isTrue();
  }

  @Test
  @DisplayName("第387轮：方法级规则不得扩散到同前缀的其他资源")
  void methodLevelRulesDoNotLeakToSiblings() {
    assertThat(blacklist.blocksMethodPath("DELETE", "/api/findings/123")).isFalse();
    assertThat(blacklist.blocksMethodPath("DELETE", "/api/findings-extra")).isFalse();
    assertThat(blacklist.blocksMethodPath("PUT", "/api/findings")).isFalse();
  }
}
