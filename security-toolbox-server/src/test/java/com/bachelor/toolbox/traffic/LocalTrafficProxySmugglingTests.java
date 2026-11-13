package com.bachelor.toolbox.traffic;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.lang.reflect.Method;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * 抓包代理请求走私（重复/冲突 Content-Length）防护——Round 16。
 *
 * <p>{@code LocalTrafficProxy} 原在 {@code rewriteHeaders} 中原样转发客户端的所有
 * {@code Content-Length} 行，且不拒绝重复/冲突的 CL —— 上游会得到两条 CL（CL.CL 去同步），
 * 构成请求走私面。本类锁定修复：① 重复/冲突 CL 在入口拒绝；② 转发时丢弃客户端 CL，
 * 只写一条与实际转发体长一致的 CL。
 */
@DisplayName("抓包代理 CL.CL 请求走私防护（Round 16）")
class LocalTrafficProxySmugglingTests {
  private final LocalTrafficProxy proxy =
      new LocalTrafficProxy(
          null,
          new com.bachelor.toolbox.target.TargetPolicyService(
              false, new com.bachelor.toolbox.target.PortRangeParser()),
          null,
          c -> {});

  private void reject(String[] lines) throws Exception {
    Method m = LocalTrafficProxy.class.getDeclaredMethod("rejectUnsupportedRequest", String[].class);
    m.setAccessible(true);
    try {
      m.invoke(proxy, (Object) lines);
    } catch (java.lang.reflect.InvocationTargetException e) {
      Throwable c = e.getCause();
      if (c instanceof RuntimeException re) throw re;
      throw new RuntimeException(c);
    }
  }

  private String rewrite(String[] lines, int bodyLen, boolean hasBody) throws Exception {
    Method m = LocalTrafficProxy.class.getDeclaredMethod(
        "rewriteHeaders", String[].class, String.class, String.class, String.class, int.class, boolean.class);
    m.setAccessible(true);
    return (String) m.invoke(proxy, lines, "POST", "/p", "HTTP/1.1", bodyLen, hasBody);
  }

  private static final String[] SINGLE_CL = {
    "POST /p HTTP/1.1", "Host: h", "Content-Length: 5", "X-A: 1"
  };
  private static final String[] DUP_CL_SAME = {
    "POST /p HTTP/1.1", "Host: h", "Content-Length: 5", "Content-Length: 5"
  };
  private static final String[] DUP_CL_DIFF = {
    "POST /p HTTP/1.1", "Host: h", "Content-Length: 5", "Content-Length: 6"
  };

  @Test
  @DisplayName("CL-1 单一 Content-Length 正常通过校验")
  void singleContentLengthOk() throws Exception {
    reject(SINGLE_CL);
  }

  @Test
  @DisplayName("CL-2 重复 Content-Length（相同值）→ 拒绝")
  void duplicateSameContentLengthRejected() {
    assertThatThrownBy(() -> reject(DUP_CL_SAME))
        .isInstanceOf(RuntimeException.class);
  }

  @Test
  @DisplayName("CL-3 冲突 Content-Length（不同值）→ 拒绝（CL.CL 走私）")
  void conflictingContentLengthRejected() {
    assertThatThrownBy(() -> reject(DUP_CL_DIFF))
        .isInstanceOf(RuntimeException.class);
  }

  @Test
  @DisplayName("CL-4 转发头只保留一条权威 Content-Length（等于实际体长），丢弃客户端 CL")
  void rewrittenHeadersHaveSingleAuthoritativeContentLength() throws Exception {
    String out = rewrite(DUP_CL_SAME, 3, true);
    // 原始的两条 Content-Length 都被丢弃，只剩一条 = 实际体长 3
    long count = out.lines().filter(l -> l.toLowerCase().startsWith("content-length:")).count();
    assertThat(count).isEqualTo(1);
    assertThat(out).contains("Content-Length: 3");
    // 客户端原始值 5 不应出现
    assertThat(out).doesNotContain("Content-Length: 5");
  }

  @Test
  @DisplayName("CL-5 无请求体且未声明 CL → 不写 Content-Length")
  void noBodyNoContentLength() throws Exception {
    String[] lines = {"GET /p HTTP/1.1", "Host: h", "X-A: 1"};
    String out = rewrite(lines, 0, false);
    assertThat(out.lines().noneMatch(l -> l.toLowerCase().startsWith("content-length:"))).isTrue();
  }
}
