package com.bachelor.toolbox.ai.capability.discovery;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

/**
 * 第289轮：{@code bash_probe} 的提权前缀拦截不得被绝对路径写法绕过。
 *
 * <p>既有实现要求提权关键字前必须是行首或 {@code ; & |} 之一或空白，因此
 * {@code /usr/bin/sudo id} 这类写法不会被识别——而它正是最直接的提权写法。
 */
class BashProbePrivilegePrefixTests {

  @Test
  void absolutePathPrivilegeEscalationIsRejected() {
    assertThatThrownBy(() -> BashProbePolicy.validateCommand("/usr/bin/sudo id"))
        .isInstanceOf(BashProbePolicy.BashProbeRejectedException.class)
        .hasMessageContaining("提权");

    assertThatThrownBy(() -> BashProbePolicy.validateCommand("cd /tmp && /usr/bin/su root"))
        .isInstanceOf(BashProbePolicy.BashProbeRejectedException.class)
        .hasMessageContaining("提权");
  }

  @Test
  void plainPrivilegeEscalationStaysRejected() {
    assertThatThrownBy(() -> BashProbePolicy.validateCommand("sudo -i"))
        .isInstanceOf(BashProbePolicy.BashProbeRejectedException.class)
        .hasMessageContaining("提权");
    assertThatThrownBy(() -> BashProbePolicy.validateCommand("id; doas id"))
        .isInstanceOf(BashProbePolicy.BashProbeRejectedException.class)
        .hasMessageContaining("提权");
  }

  @Test
  void ordinaryCommandsAreStillAllowed() {
    assertThatCode(() -> BashProbePolicy.validateCommand("curl -s -o /dev/null -w '%{http_code}' http://192.168.222.158/"))
        .doesNotThrowAnyException();
    // 名称里含 su/sudo 子串但并非提权命令的普通单词不得误杀
    assertThatCode(() -> BashProbePolicy.validateCommand("nmap -sV 192.168.222.158"))
        .doesNotThrowAnyException();
    assertThatCode(() -> BashProbePolicy.validateCommand("echo sudoku"))
        .doesNotThrowAnyException();
  }
}

