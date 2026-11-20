package com.bachelor.toolbox.report;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.Test;

/** Round 238：ReportFormatters 的 JSON 美化与严重度汇总边界回归。 */
class ReportFormattersJsonTests {
  @Test
  void malformedJsonIsReturnedVerbatim() {
    String raw = "{\"unterminated\":";
    assertThat(ReportFormatters.prettyPrintJson(raw)).isEqualTo(raw);
  }

  @Test
  void validJsonIsPrettyPrinted() {
    String pretty = ReportFormatters.prettyPrintJson("{\"b\":2,\"a\":1}");
    assertThat(pretty).contains("\n").contains("\"a\"").contains("\"b\"");
  }

  @Test
  void severityChipBarUsesOnlyFixedLabelsAndNumericCounts() {
    String html = ReportFormatters.severityChipBar(List.of());
    assertThat(html).contains("severity-hint").doesNotContain("<script");
  }
}
