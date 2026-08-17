package com.bachelor.toolbox.tool;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.target.TargetPolicyService;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;

class XrayScanToolTests {
  private final XrayScanTool tool =
      new XrayScanTool(
          mock(TargetPolicyService.class),
          new ObjectMapper(),
          mock(ScannerPocSelectionService.class),
          "xray",
          60);

  @Test
  void buildsCommandWithSingleOrMultiplePocs() {
    Path output = Path.of("result.json");
    List<String> command =
        tool.buildCommand(
            URI.create("https://127.0.0.1:8443"),
            List.of(poc("poc-a", "XP-1234567890ABCDEF12345678"), poc("poc-b", "XP-FEDCBA0987654321FEDCBA09")),
            output);

    assertThat(command).containsSubsequence("--plugins", "phantasm");
    assertThat(command).containsSubsequence("--poc", "poc-a,poc-b");
    assertThat(command).containsSubsequence("--json-output", output.toString());
  }

  @Test
  void allPocsUsesScannerAllModeWithoutExpandingIdsIntoTheCommand() {
    Path output = Path.of("result.json");
    List<String> command =
        tool.buildCommand(
            URI.create("https://127.0.0.1:8443"),
            List.of(poc("poc-a"), poc("poc-b")),
            output,
            true);

    assertThat(command).containsSubsequence("--plugins", "phantasm");
    assertThat(command).doesNotContain("--poc", "poc-a,poc-b");
    assertThat(command).containsSubsequence("--json-output", output.toString());
  }

  @Test
  void parsesJsonResultIntoFindings() {
    String json =
        """
[
  {
    "plugin": "phantasm",
    "poc": "xray-test-poc",
    "target": {"url": "https://127.0.0.1:8443/login"},
    "detail": {"vuln_class": "Xray issue", "level": "high"}
  }
]
""";

    ToolExecutionResult result =
        tool.parseOutput(URI.create("https://127.0.0.1:8443"), List.of(poc("xray-test-poc")), json);

    assertThat(result.findings()).hasSize(1);
    assertThat(result.findings().get(0).severity()).isEqualTo("HIGH");
    assertThat(result.findings().get(0).vulnerabilityCode())
        .isEqualTo("XP-1234567890ABCDEF12345678");
    assertThat(result.data()).containsEntry("selectedPocCount", 1).containsEntry("matchCount", 1);
  }

  @Test
  void rejectsOutOfScopeMatch() {
    String json =
        """
[
  {
    "plugin": "phantasm",
    "poc": "xray-test-poc",
    "target": "https://192.0.2.10:8443/login",
    "detail": {"vuln_class": "Xray issue", "level": "high"}
  }
]
""";

    assertThatThrownBy(
            () ->
                tool.parseOutput(
                    URI.create("https://127.0.0.1:8443"), List.of(poc("xray-test-poc")), json))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("授权范围外");
  }

  private ScannerPocSelectionService.SelectedPoc poc(String externalId) {
    return poc(externalId, "XP-1234567890ABCDEF12345678");
  }

  private ScannerPocSelectionService.SelectedPoc poc(String externalId, String code) {
    return new ScannerPocSelectionService.SelectedPoc(
        code,
        externalId,
        "Xray issue",
        "HIGH",
        Path.of("poc.yaml"),
        "0".repeat(64));
  }
}
