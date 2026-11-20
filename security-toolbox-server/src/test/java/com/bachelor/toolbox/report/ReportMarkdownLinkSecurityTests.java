package com.bachelor.toolbox.report;

import static org.junit.jupiter.api.Assertions.assertFalse;

import org.junit.jupiter.api.Test;

/** 临时安全回归：报告 Markdown 不得保留脚本/数据协议链接。 */
class ReportMarkdownLinkSecurityTests {
  @Test
  void stripsDangerousLinksAndRawScripts() {
    String rendered =
        ReportMarkdown.render(
            "[click](javascript:alert(1)) [data](data:text/html,<script>alert(1)</script>)"
                + " <a href=\"javascript:alert(2)\">raw</a><script>alert(3)</script>");
    assertFalse(rendered.toLowerCase().contains("javascript:"));
    assertFalse(rendered.toLowerCase().contains("data:text/html"));
    assertFalse(rendered.toLowerCase().contains("<script"));
  }
}
