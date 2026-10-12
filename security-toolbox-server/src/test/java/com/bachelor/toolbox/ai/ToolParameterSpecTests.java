package com.bachelor.toolbox.ai;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.bachelor.toolbox.common.ApiException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/**
 * {@link ToolParameterSpec} 的取值规格与<strong>边界语义</strong>验证。
 *
 * <h2>为什么边界语义值得单独测</h2>
 *
 * <p>把三份重复实现统一到本类时，最容易引入的不是"枚举值写错"，而是
 * <strong>"缺失"与"显式 null"的处理差异</strong>：
 *
 * <pre>
 * // 原实现（执行侧）
 * String mode = Objects.toString(parameters.getOrDefault("mode", "quick"), "");
 * // 键缺失     → "quick"          ✅
 * // {"mode":null} → Objects.toString(null, "") = "" → 抛异常 ✅（fail-closed）
 *
 * // 若统一时写成"null 也走默认值"
 * // {"mode":null} → "quick"       🔴 fail-open：把非法输入静默变成合法执行
 * </pre>
 *
 * <p>这个差异只在"键存在且值为 {@code null}"时触发，而 LLM 生成的 JSON
 * <strong>完全可能产生 {@code {"mode": null}}</strong>——因此必须锁死。
 *
 * <p>本类同时验证：<strong>缺失走默认（不抛）</strong> 与 <strong>显式 null 拒绝</strong> 两种行为。
 */
@DisplayName("工具参数取值规格（单一事实来源）")
class ToolParameterSpecTests {

  @Nested
  @DisplayName("A. D-1 http_security_check.check")
  class HttpCheck {

    @Test
    @DisplayName("A-1 合法取值通过（大小写敏感）")
    void acceptsValidValues() {
      for (String valid : ToolParameterSpec.HTTP_CHECK_TYPES) {
        assertEquals(valid, ToolParameterSpec.requireHttpCheck(valid));
      }
    }

    @Test
    @DisplayName("A-2 非法取值拒绝")
    void rejectsInvalidValues() {
      assertThrows(ApiException.class, () -> ToolParameterSpec.requireHttpCheck("NOT_A_CHECK"));
      assertThrows(ApiException.class, () -> ToolParameterSpec.requireHttpCheck("COOKIES"));
    }

    @Test
    @DisplayName("A-3 显式 null 拒绝（不得静默取默认）")
    void rejectsExplicitNull() {
      assertThrows(
          ApiException.class,
          () -> ToolParameterSpec.requireHttpCheck(null),
          "显式 null 是非法取值，必须拒绝而不是静默放行");
    }
  }

  @Nested
  @DisplayName("B. D-2 nmap_service_scan.mode")
  class NmapMode {

    @Test
    @DisplayName("B-1 合法取值通过")
    void acceptsValidValues() {
      assertEquals("quick", ToolParameterSpec.requireNmapMode("quick"));
      assertEquals("service", ToolParameterSpec.requireNmapMode("service"));
    }

    @Test
    @DisplayName("B-2 非法取值拒绝")
    void rejectsInvalidValues() {
      assertThrows(ApiException.class, () -> ToolParameterSpec.requireNmapMode("NOT_A_MODE"));
    }

    @Test
    @DisplayName("B-3 显式 null 拒绝（不得静默降级为 quick）")
    void rejectsExplicitNull() {
      // 这是本类最关键的一条：若 null 被静默当作 "quick"，LLM 传 {"mode": null}
      // 就会绕过"取值必须明确"的约束。
      assertThrows(
          ApiException.class,
          () -> ToolParameterSpec.requireNmapMode(null),
          "显式 null 必须拒绝——静默取默认会把非法输入变成合法执行（fail-open）");
    }

    @Test
    @DisplayName("B-4 默认值常量本身合法（缺失时调用方取它）")
    void defaultModeIsItselfValid() {
      assertEquals(
          ToolParameterSpec.NMAP_DEFAULT_MODE,
          ToolParameterSpec.requireNmapMode(ToolParameterSpec.NMAP_DEFAULT_MODE),
          "默认值必须能通过自身校验，否则'键缺失'路径会抛异常");
    }
  }

  @Nested
  @DisplayName("C. D-3 fscan_scan.vulnMode")
  class FscanVulnMode {

    @Test
    @DisplayName("C-1 合法取值通过且归一化为大写")
    void acceptsAndNormalizes() {
      assertEquals("SAFE", ToolParameterSpec.requireFscanVulnMode("safe"));
      assertEquals("FINGERPRINT", ToolParameterSpec.requireFscanVulnMode("fingerprint"));
      assertEquals("FULL", ToolParameterSpec.requireFscanVulnMode("full"));
      assertEquals("FULL", ToolParameterSpec.requireFscanVulnMode("FULL"));
    }

    @Test
    @DisplayName("C-2 非法取值拒绝")
    void rejectsInvalidValues() {
      assertThrows(
          ApiException.class, () -> ToolParameterSpec.requireFscanVulnMode("ARBITRARY_MODE"));
    }

    @Test
    @DisplayName("C-3 显式 null 拒绝（不得静默降级为 SAFE）")
    void rejectsExplicitNull() {
      assertThrows(
          ApiException.class,
          () -> ToolParameterSpec.requireFscanVulnMode(null),
          "显式 null 必须拒绝——FULL 会启用漏洞利用类检测，静默取默认会掩盖调用方意图");
    }

    @Test
    @DisplayName("C-4 默认值常量本身合法")
    void defaultModeIsItselfValid() {
      assertEquals(
          "SAFE",
          ToolParameterSpec.requireFscanVulnMode(ToolParameterSpec.FSCAN_DEFAULT_VULN_MODE));
    }

    @Test
    @DisplayName("C-5 FULL 必须显式指定（不可被默认值意外提升）")
    void fullIsNeverADefault() {
      // 安全性质：FULL 启用漏洞利用类检测，默认值绝不能是 FULL。
      assertThrows(
          ApiException.class,
          () -> ToolParameterSpec.requireFscanVulnMode(""),
          "空串不得被当作 FULL 或默认值放行");
      // 常量本身是小写（由 requireFscanVulnMode 归一化为大写）。
      assertEquals("safe", ToolParameterSpec.FSCAN_DEFAULT_VULN_MODE, "默认必须是 safe");
      assertEquals(
          "SAFE",
          ToolParameterSpec.requireFscanVulnMode(ToolParameterSpec.FSCAN_DEFAULT_VULN_MODE),
          "默认值归一化后必须是 SAFE，绝不能是 FULL");
    }
  }

  @Nested
  @DisplayName("D. D-4 zap_scan.strength")
  class ZapStrength {

    @Test
    @DisplayName("D-1 合法取值通过且归一化为大写")
    void acceptsAndNormalizes() {
      assertEquals("LOW", ToolParameterSpec.requireZapStrength("low"));
      assertEquals("INSANE", ToolParameterSpec.requireZapStrength("INSANE"));
    }

    @Test
    @DisplayName("D-2 非法取值拒绝")
    void rejectsInvalidValues() {
      assertThrows(ApiException.class, () -> ToolParameterSpec.requireZapStrength("NOT_A_LEVEL"));
    }

    @Test
    @DisplayName("D-3 显式 null 拒绝")
    void rejectsExplicitNull() {
      assertThrows(ApiException.class, () -> ToolParameterSpec.requireZapStrength(null));
    }
  }

  @Nested
  @DisplayName("E. MSF 模块前缀")
  class MsfModule {

    @Test
    @DisplayName("E-1 auxiliary/ 与 exploit/ 前缀通过")
    void acceptsAllowedPrefixes() {
      assertEquals("auxiliary/scanner/ssh", ToolParameterSpec.requireMsfModule("auxiliary/scanner/ssh"));
      assertEquals("exploit/windows/smb", ToolParameterSpec.requireMsfModule("exploit/windows/smb"));
    }

    @Test
    @DisplayName("E-2 其他前缀拒绝（含 payload/ 与裸模块名）")
    void rejectsOtherPrefixes() {
      assertThrows(
          ApiException.class,
          () -> ToolParameterSpec.requireMsfModule("payload/windows/x64/meterpreter"));
      assertThrows(ApiException.class, () -> ToolParameterSpec.requireMsfModule("scanner/ssh"));
      assertThrows(ApiException.class, () -> ToolParameterSpec.requireMsfModule(null));
    }

    @Test
    @DisplayName("E-3 前缀常量与执行侧语义一致")
    void prefixConstantsMatchSemantics() {
      assertEquals(2, ToolParameterSpec.MSF_MODULE_PREFIXES.size());
      assertEquals("auxiliary/", ToolParameterSpec.MSF_MODULE_PREFIXES.get(0));
      assertEquals("exploit/", ToolParameterSpec.MSF_MODULE_PREFIXES.get(1));
    }
  }
}
