package com.bachelor.toolbox.ai;

import com.bachelor.toolbox.common.ApiException;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;

/**
 * 工具参数的<strong>取值规格</strong>——护栏侧与执行侧共用的<strong>单一事实来源</strong>。
 *
 * <h2>为什么需要本类（消除 D-1..D-4 规则漂移）</h2>
 *
 * <p>同一套"工具参数校验"原先存在<strong>三份独立实现</strong>：
 *
 * <ol>
 *   <li>{@code AiTaskDispatchService.validateAndNormalize}（执行侧，原始实现）
 *   <li>{@code EndpointParameterPolicy}（护栏侧副本，<strong>缺 D-1..D-4 四类枚举规则</strong>）
 *   <li>{@code ToolParameterPolicy}（核心能力侧第三份）
 * </ol>
 *
 * <p>护栏侧副本因"规则字面量各写一份"而漂移——{@code fscan_scan} 的 {@code vulnMode} 在护栏侧
 * <strong>没有枚举校验</strong>，因此可经通用原语请求 {@code FULL}（启用漏洞利用类检测）。
 *
 * <p>本类把取值规格<strong>抽取为共享常量</strong>，两侧引用同一份定义：
 * <strong>只要有人改了一处，另一处立即同步</strong>——漂移在结构上不可能发生。
 *
 * <h2>与"漂移断言"的区别</h2>
 *
 * <p>{@code ToolParameterPolicy.assertNoDrift} 只是把"静默漂移"变成"测试失败"——<strong>检测而不消除</strong>。
 * 本类<strong>消除</strong>重复：不存在第二份字面量可比对。
 */
public final class ToolParameterSpec {

  private ToolParameterSpec() {}

  // ------------------------------------------------------------------ D-1..D-4 取值枚举

  /** {@code http_security_check} 的 {@code check} 取值（D-1）。 */
  public static final Set<String> HTTP_CHECK_TYPES =
      Set.of("cookies", "cors", "methods", "disclosure");

  /** {@code nmap_service_scan} 的 {@code mode} 取值（D-2）。 */
  public static final Set<String> NMAP_MODES = Set.of("quick", "service");

  /** {@code nmap_service_scan} 的默认 {@code mode}。 */
  public static final String NMAP_DEFAULT_MODE = "quick";

  /** {@code fscan_scan} 的 {@code vulnMode} 取值（D-3）。注意 {@code FULL} 启用漏洞利用类检测。 */
  public static final Set<String> FSCAN_VULN_MODES = Set.of("SAFE", "FINGERPRINT", "FULL");

  /** {@code fscan_scan} 的默认 {@code vulnMode}。 */
  public static final String FSCAN_DEFAULT_VULN_MODE = "safe";

  /** {@code zap_scan} 的 {@code strength} 取值（D-4）。 */
  public static final Set<String> ZAP_STRENGTHS = Set.of("LOW", "MEDIUM", "HIGH", "INSANE");

  /** MSF 模块允许的前缀。 */
  public static final List<String> MSF_MODULE_PREFIXES = List.of("auxiliary/", "exploit/");

  // ------------------------------------------------------------------ 校验方法（两侧共用）

  /**
   * 校验 {@code http_security_check} 的 {@code check} 取值并归一化（D-1）。
   *
   * @return 归一化后的取值（已 trim）
   */
  public static String requireHttpCheck(Object rawCheck) {
    String check = Objects.toString(rawCheck, "");
    if (!HTTP_CHECK_TYPES.contains(check)) {
      throw new ApiException("HTTP 检查类型不受支持: " + check);
    }
    return check;
  }

  /**
   * 校验 {@code nmap_service_scan} 的 {@code mode} 取值并归一化（D-2）。
   *
   * <p><strong>注意"缺失"与"显式 null"的区别</strong>：调用方应先用
   * {@code getOrDefault(key, 默认值)} 处理"键缺失"，本方法只负责校验值本身。
   * 若键<em>存在</em>但值为 {@code null}（LLM 生成的 JSON 可能出现 {@code {"mode": null}}），
   * 说明调用方给了明确但非法的取值——应当<strong>拒绝</strong>而不是静默取默认值
   * （静默取默认会把"非法输入"变成"合法执行"，是 fail-open）。
   */
  public static String requireNmapMode(Object rawMode) {
    String mode = Objects.toString(rawMode, "");
    if (!NMAP_MODES.contains(mode)) {
      throw new ApiException("Nmap mode 仅支持 quick 或 service: " + mode);
    }
    return mode;
  }

  /**
   * 校验 {@code fscan_scan} 的 {@code vulnMode} 取值并归一化（D-3）。
   *
   * <p><strong>安全意义</strong>：{@code FULL} 会启用漏洞利用类检测，必须显式指定，不可静默提升。
   *
   * <p>与 {@link #requireNmapMode} 同样区分"缺失"与"显式 null"：后者应拒绝。
   */
  public static String requireFscanVulnMode(Object rawMode) {
    String mode = Objects.toString(rawMode, "").toUpperCase(Locale.ROOT);
    if (!FSCAN_VULN_MODES.contains(mode)) {
      throw new ApiException("fscan 模式仅支持 safe、fingerprint 或 full: " + mode);
    }
    return mode;
  }

  /** 校验 {@code zap_scan} 的 {@code strength} 取值并归一化（D-4）。 */
  public static String requireZapStrength(Object rawStrength) {
    String strength = Objects.toString(rawStrength, "").toUpperCase(Locale.ROOT);
    if (!ZAP_STRENGTHS.contains(strength)) {
      throw new ApiException("ZAP 扫描强度仅支持 LOW、MEDIUM、HIGH 或 INSANE: " + strength);
    }
    return strength;
  }

  /** 校验 MSF 模块前缀（执行侧与护栏侧共用）。 */
  public static String requireMsfModule(Object rawModule) {
    String module = Objects.toString(rawModule, "").trim().toLowerCase(Locale.ROOT);
    boolean allowed =
        MSF_MODULE_PREFIXES.stream().anyMatch(module::startsWith);
    if (!allowed) {
      throw new ApiException("MSF 模块仅允许 auxiliary/ 或 exploit/ 前缀: " + module);
    }
    return module;
  }
}
