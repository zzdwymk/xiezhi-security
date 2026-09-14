package com.bachelor.toolbox.tool;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import com.bachelor.toolbox.dependency.ExecutableLocator;
import com.bachelor.toolbox.target.TargetPolicyService;
import org.junit.jupiter.api.Test;

class SqlmapScanToolTests {
  private final SqlmapScanTool tool =
      new SqlmapScanTool(
          mock(TargetPolicyService.class), mock(ExecutableLocator.class), "sqlmap", 60);

  @Test
  void parsesConfirmedInjectionIntoFindings() {
    String output =
        """

        [INFO] testing connection to the target URL
        [WARNING] the back-end DBMS is MySQL
        [INFO] confirming SQL injection on the specified URL
        sqlmap identified the following injection point(s) with a total of 1 HTTP(s) request:
        ---
        Parameter: id (GET)
            Type: boolean-based blind
            Title: AND boolean-based blind - WHERE or HAVING clause
        Type: time-based blind
            Title: MySQL >= 5.0.12 AND time-based blind (comment)
        ---
        [INFO] the back-end DBMS is MySQL
        [INFO] fetched data logged to text files under
        """;

    ToolExecutionResult result = tool.parseOutput("http://10.0.0.1/less?id=1", output);

    assertThat(result.data()).containsEntry("vulnerable", true);
    assertThat(result.data()).containsEntry("parameter", "id (GET)");
    assertThat(result.findings()).hasSize(1);
    assertThat(result.findings().get(0).vulnerabilityCode()).isEqualTo("STB-SQLMAP-001");
    assertThat(result.findings().get(0).severity()).isEqualTo("HIGH");
  }

  @Test
  void reportsNotVulnerableWhenNoInjectionBlock() {
    ToolExecutionResult result = tool.parseOutput("http://10.0.0.1/page", "已对目标发起了请求，未检测到注入点");

    assertThat(result.data()).containsEntry("vulnerable", false);
    assertThat(result.findings()).isEmpty();
  }
}