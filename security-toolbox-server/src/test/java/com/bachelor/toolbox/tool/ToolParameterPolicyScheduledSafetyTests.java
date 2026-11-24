package com.bachelor.toolbox.tool;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.bachelor.toolbox.common.ApiException;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class ToolParameterPolicyScheduledSafetyTests {
  private static final String CODE = "NC-0123456789ABCDEF01234567";
  private static final String SAFE = ScannerPocSelectionService.SAFE_ONLY_PARAMETER;

  @ParameterizedTest
  @ValueSource(strings = {"nuclei_scan", "afrog_scan", "xray_scan"})
  void trustedScheduledSafetyFlagPassesExecutionEntryWithoutRemovingSafety(String tool) {
    Map<String, Object> parameters = Map.of("pocCodes", List.of(CODE), SAFE, true);
    assertThatCode(() -> ToolParameterPolicy.validateAtExecutionEntry(tool, parameters))
        .doesNotThrowAnyException();
    org.assertj.core.api.Assertions.assertThat(parameters).containsEntry(SAFE, true);
  }

  @ParameterizedTest
  @ValueSource(strings = {"nuclei_scan", "afrog_scan", "xray_scan"})
  void userCannotSubmitScheduledSafetyFlag(String tool) {
    assertThatThrownBy(() -> ToolParameterPolicy.rejectUserSuppliedFrameworkKeys(
        Map.of("pocCodes", List.of(CODE), SAFE, true)))
        .isInstanceOf(ApiException.class).hasMessageContaining("内部保留键");
  }

  @ParameterizedTest
  @ValueSource(strings = {"http_headers", "tls_config", "nmap_service_scan", "site_crawl"})
  void safetyFlagIsNotAUniversalWhitelistException(String tool) {
    assertThatThrownBy(() -> ToolParameterPolicy.validateAtExecutionEntry(tool, Map.of(SAFE, true)))
        .isInstanceOf(ApiException.class);
  }

  @ParameterizedTest
  @ValueSource(strings = {"nuclei_scan", "afrog_scan", "xray_scan"})
  void trustedSafetyFlagCannotBeFalseOrString(String tool) {
    for (Object value : List.of(false, "true", 1)) {
      assertThatThrownBy(() -> ToolParameterPolicy.validateAtExecutionEntry(tool,
          Map.of("pocCodes", List.of(CODE), SAFE, value))).isInstanceOf(ApiException.class);
    }
  }
}
