package com.bachelor.toolbox.report;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

/** Round 235：报告展示层的 JSON 文本必须按字符预算截断。 */
class ReportServiceJsonBudgetTests {
  @Test
  void smallJsonIsUnchanged() {
    assertThat(ReportService.limitJsonForReport("{\"a\":1}")).isEqualTo("{\"a\":1}");
  }

  @Test
  void oversizedJsonIsBoundedAndMarked() {
    String huge = "x".repeat(ReportService.MAX_REPORT_JSON_CHARS + 10);
    String limited = ReportService.limitJsonForReport(huge);
    assertThat(limited).hasSizeLessThanOrEqualTo(ReportService.MAX_REPORT_JSON_CHARS + 80);
    assertThat(limited).contains("报告展示已截断");
    assertThat(limited).contains("原始长度");
  }
}
