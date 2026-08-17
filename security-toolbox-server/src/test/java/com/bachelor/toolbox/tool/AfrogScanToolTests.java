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

class AfrogScanToolTests {
  private final AfrogScanTool tool =
      new AfrogScanTool(
          mock(TargetPolicyService.class),
          new ObjectMapper(),
          mock(ScannerPocSelectionService.class),
          "afrog",
          60);

  @Test
  void buildsCommandForSelectedPocDirectory() {
    URI target = URI.create("https://127.0.0.1:8443");
    Path pocs = Path.of("selected-pocs");
    Path output = Path.of("result.json");

    List<String> command = tool.buildCommand(target, pocs, output);

    assertThat(command).containsSubsequence("-t", target.toString(), "-P", pocs.toString());
    assertThat(command).containsSubsequence("-json", output.toString());
    assertThat(command).contains("-disable-update-check", "-curated", "off", "-silent");
  }

  @Test
  void parsesJsonArrayIntoFindings() {
    String json =
        """
[
  {
    "id": "afrog-test-poc",
    "fulltarget": "https://127.0.0.1:8443/login",
    "info": {
      "name": "Afrog issue",
      "severity": "high",
      "description": "Matched by Afrog"
    }
  }
]
""";

    ToolExecutionResult result =
        tool.parseOutput(URI.create("https://127.0.0.1:8443"), List.of(poc("afrog-test-poc")), json);

    assertThat(result.findings()).hasSize(1);
    assertThat(result.findings().get(0).severity()).isEqualTo("HIGH");
    assertThat(result.findings().get(0).vulnerabilityCode())
        .isEqualTo("AP-1234567890ABCDEF12345678");
    assertThat(result.data()).containsEntry("selectedPocCount", 1).containsEntry("matchCount", 1);
  }

  @Test
  void rejectsOutOfScopeMatch() {
    String json =
        """
[
  {"id": "afrog-test-poc", "fulltarget": "https://192.0.2.10:8443/", "info": {"name": "Issue"}}
]
""";

    assertThatThrownBy(
            () ->
                tool.parseOutput(
                    URI.create("https://127.0.0.1:8443"), List.of(poc("afrog-test-poc")), json))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("授权范围外");
  }

  private ScannerPocSelectionService.SelectedPoc poc(String externalId) {
    return new ScannerPocSelectionService.SelectedPoc(
        "AP-1234567890ABCDEF12345678",
        externalId,
        "Afrog issue",
        "HIGH",
        Path.of("poc.yaml"),
        "0".repeat(64));
  }
}
