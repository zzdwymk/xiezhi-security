package com.bachelor.toolbox.report;
import static org.assertj.core.api.Assertions.assertThat;
import org.junit.jupiter.api.Test;
class ReportIdSortContractTests {
 @Test void scriptAvoidsLossyIntegerAndFloatingPointIdConversion(){
  assertThat(ReportFormatters.REPORT_FILTER_SCRIPT).doesNotContain("~~", "parseInt", "Number(");
  assertThat(ReportFormatters.REPORT_FILTER_SCRIPT).contains("return idcmp(b,a)","return idcmp(a,b)","x.length-y.length");
 }
}
