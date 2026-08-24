package com.bachelor.toolbox.tool;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

import com.bachelor.toolbox.target.PortRangeParser;
import com.bachelor.toolbox.target.TargetPolicyService;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

class NucleiScanToolTests {
  private final NucleiScanTool tool =
      new NucleiScanTool(
          mock(TargetPolicyService.class),
          new PortRangeParser(),
          new ObjectMapper(),
          "nuclei",
          ".",
          65535,
          60);

  @Test
  void buildsBoundedAuthorizedCommand() {
    Path targetList = Path.of("authorized-targets.txt");

    List<String> command = tool.buildCommand(targetList);

    assertThat(command).containsSubsequence("-list", targetList.toString(), "-pt", "http,ssl");
    List<String> templates = new ArrayList<>();
    for (int i = 0; i < command.size() - 1; i++) {
      if ("-templates".equals(command.get(i))) {
        templates.add(command.get(i + 1));
      }
    }
    assertThat(templates).hasSize(4);
    assertThat(templates.get(0)).endsWith(Path.of("http", "exposures").toString());
    assertThat(templates.get(1)).endsWith(Path.of("http", "misconfiguration").toString());
    assertThat(templates.get(2)).endsWith(Path.of("http", "technologies").toString());
    assertThat(templates.get(3)).endsWith(Path.of("ssl").toString());
    assertThat(command).contains("-jsonl", "-duc", "-dr", "-ni", "-dut", "-or", "-ot");
    assertThat(command).containsSubsequence("-stats-json", "-si", "1");
    assertThat(command).contains("-etags");
    assertThat(command.get(command.indexOf("-etags") + 1))
        .contains("intrusive", "bruteforce", "rce", "sqli");
    assertThat(command).doesNotContain("-port");
    assertThat(command).doesNotContain("-headless", "-code", "-tags", "-include-tags");
  }

  @Test
  void parsesJsonLinesIntoFindings() {
    String jsonl =
        """
{"template-id":"CVE-2025-0001","info":{"name":"Example issue","severity":"high"},"matched-at":"http://127.0.0.1:8080"}
non-json diagnostic
""";

    ToolExecutionResult result = tool.parseOutput("127.0.0.1", "8080", jsonl);

    assertThat(result.findings()).hasSize(1);
    assertThat(result.findings().get(0).severity()).isEqualTo("HIGH");
    assertThat(result.findings().get(0).evidence())
        .contains("CVE-2025-0001")
        .contains("127.0.0.1:8080");
    assertThat(result.findings().get(0).vulnerabilityCode()).startsWith("NT-");
    assertThat(result.data()).containsEntry("matchCount", 1);
  }

  @Test
  void rejectsOutOfScopeNucleiMatchInsteadOfIgnoringIt() {
    String jsonl =
        """
{"template-id":"real-template","info":{"name":"Example","severity":"high"},"matched-at":"http://192.0.2.10:8080"}
""";

    assertThatThrownBy(() -> tool.parseOutput("127.0.0.1", "8080", jsonl))
        .isInstanceOf(com.bachelor.toolbox.common.ApiException.class)
        .hasMessageContaining("授权范围外");
  }
}
