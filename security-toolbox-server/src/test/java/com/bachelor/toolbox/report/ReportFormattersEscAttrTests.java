package com.bachelor.toolbox.report;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

/** Round 237：HTML 属性转义必须覆盖单引号，避免未来单引号属性复用出现注入。 */
class ReportFormattersEscAttrTests {
  @Test
  void escapesBothQuoteKindsAndAngleBrackets() {
    String escaped = ReportFormatters.escAttr("a'b\"c<>&");
    assertThat(escaped).contains("&#39;").contains("&quot;").contains("&lt;").contains("&gt;");
    assertThat(escaped).doesNotContain("'").doesNotContain("\"");
  }
}
