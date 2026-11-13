package com.bachelor.toolbox.tool;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.msf.MsfScanEngine;
import com.bachelor.toolbox.target.PortRangeParser;
import com.bachelor.toolbox.target.TargetPolicyService;
import java.lang.reflect.Method;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * MSF 选项命令注入回归——Round 15。
 *
 * <p>选项键值会被拼进 {@code msfconsole -x "set KEY VALUE;"} 脚本。原实现只校验了
 * <strong>值</strong>不含 {@code ;}/换行，却未校验<strong>键</strong>，攻击者可用
 * {@code "A;setg RHOSTS 8.8.8.8"} 之类的键注入额外 msfconsole 命令（改 RHOSTS 越权/RCE 前置）。
 * 本类锁定修复后的严格键值校验。
 */
@DisplayName("MSF 选项命令注入防护（Round 15）")
class MsfOptionInjectionTests {
  private final MsfScanTool tool =
      new MsfScanTool(
          new TargetPolicyService(false, new PortRangeParser()),
          candidates -> java.util.Optional.of(Path.of("msfconsole.exe")),
          "msfconsole",
          600,
          new org.springframework.beans.factory.ObjectProvider<MsfScanEngine>() {
            @Override public MsfScanEngine getObject() { return null; }
            @Override public MsfScanEngine getObject(Object... args) { return null; }
          });

  @SuppressWarnings("unchecked")
  private Map<String, String> sanitize(Map<String, Object> options) {
    Map<String, Object> params = new LinkedHashMap<>();
    params.put("options", options);
    try {
      Method m = MsfScanTool.class.getDeclaredMethod("sanitizedOptions", Map.class);
      m.setAccessible(true);
      return (Map<String, String>) m.invoke(tool, params);
    } catch (java.lang.reflect.InvocationTargetException e) {
      Throwable cause = e.getCause();
      if (cause instanceof RuntimeException re) {
        throw re;
      }
      throw new RuntimeException(cause);
    } catch (ReflectiveOperationException e) {
      throw new RuntimeException(e);
    }
  }

  @Test
  @DisplayName("INJ-1 合法选项通过")
  void validOptionsPass() {
    Map<String, String> clean = sanitize(Map.of("USERNAME", "root", "THREADS", "4"));
    assertThat(clean).containsEntry("USERNAME", "root").containsEntry("THREADS", "4");
  }

  @Test
  @DisplayName("INJ-2 键中注入 ';' 追加 msfconsole 命令 → 拒绝")
  void keySemicolonRejected() {
    assertThatThrownBy(() -> sanitize(Map.of("A;setg RHOSTS 8.8.8.8", "1")))
        .isInstanceOf(ApiException.class);
  }

  @Test
  @DisplayName("INJ-3 键中含空格/换行/其他元字符 → 拒绝")
  void keyIllegalCharsRejected() {
    assertThatThrownBy(() -> sanitize(Map.of("A B", "1"))).isInstanceOf(ApiException.class);
    assertThatThrownBy(() -> sanitize(Map.of("A\nB", "1"))).isInstanceOf(ApiException.class);
    assertThatThrownBy(() -> sanitize(Map.of("A$X", "1"))).isInstanceOf(ApiException.class);
  }

  @Test
  @DisplayName("INJ-4 值中注入 ';' / 换行 / 回车 / 控制字符 → 拒绝")
  void valueInjectionRejected() {
    assertThatThrownBy(() -> sanitize(Map.of("USERNAME", "root;setg RHOSTS 8.8.8.8")))
        .isInstanceOf(ApiException.class);
    assertThatThrownBy(() -> sanitize(Map.of("USERNAME", "root\nshell"))).isInstanceOf(ApiException.class);
    assertThatThrownBy(() -> sanitize(Map.of("USERNAME", "root\rmore"))).isInstanceOf(ApiException.class);
    assertThatThrownBy(() -> sanitize(Map.of("USERNAME", "ro\u0007ot"))).isInstanceOf(ApiException.class);
  }

  @Test
  @DisplayName("INJ-5 禁止覆盖 RHOSTS/RPORT/PAYLOAD 等边界项（键名大小写不敏感）")
  void forbiddenOverrideRejected() {
    assertThatThrownBy(() -> sanitize(Map.of("RHOSTS", "8.8.8.8"))).isInstanceOf(ApiException.class);
    assertThatThrownBy(() -> sanitize(Map.of("rport", "22"))).isInstanceOf(ApiException.class);
    assertThatThrownBy(() -> sanitize(Map.of("Payload", "x"))).isInstanceOf(ApiException.class);
  }
}
