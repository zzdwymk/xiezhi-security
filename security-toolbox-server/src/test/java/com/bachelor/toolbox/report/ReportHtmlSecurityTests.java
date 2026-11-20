package com.bachelor.toolbox.report;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

/** Round 231：报告 HTML 自身必须携带 CSP，下载后直接打开也受脚本白名单约束。 */
class ReportHtmlSecurityTests {
  @Test
  void addsNonceMetaAndRestrictsScripts() {
    String secured =
        ReportHtmlSecurity.secure(
            "<!doctype html><html><head></head><body><script>alert(1)</script></body></html>");

    assertThat(secured).contains("http-equiv=\"Content-Security-Policy\"");
    assertThat(secured).contains("default-src 'none'");
    assertThat(secured).contains("script-src 'nonce-");
    assertThat(secured).containsPattern("<script nonce=\"[a-f0-9]{32}\">");
    String nonce =
        secured.replaceAll("(?s).*script-src 'nonce-([a-f0-9]{32})'.*", "$1");
    assertThat(secured).contains("nonce=\"" + nonce + "\"");
  }
}
