package com.bachelor.toolbox.msf;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.PortRangeParser;
import com.bachelor.toolbox.target.TargetPolicyService;
import com.bachelor.toolbox.tool.FindingDraft;
import com.bachelor.toolbox.tool.MsfScanTool;
import com.bachelor.toolbox.tool.ToolExecutionObserver;
import com.bachelor.toolbox.tool.ToolExecutionResult;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class MsfScanEngineTests {
  private MsfScanTool tool;
  private MsfScanEngine engine;
  private AuthorizedTarget target;

  @BeforeEach
  void setUp() {
    tool = mock(MsfScanTool.class);
    engine = new MsfScanEngine(tool, new TargetPolicyService(false, new PortRangeParser()));
    target = new AuthorizedTarget();
    target.setEnabled(true);
    target.setTargetValue("127.0.0.1");
    target.setAllowedPorts("1-65535");
  }

  @Test
  void runManyAgregatesResultsAndDeduplicatesByVulnerabilityCode() throws Exception {
    when(tool.execute(any(), any(), any(ToolExecutionObserver.class)))
        .thenReturn(
            new ToolExecutionResult(
                "ok",
                Map.of("matchCount", 1),
                List.of(
                    new FindingDraft(
                        "SSH Login", "MEDIUM", "d", "e", "r",
                        MsfModuleCatalogService.stableCodeFor("auxiliary/scanner/ssh/ssh_login")))))
        .thenReturn(
            new ToolExecutionResult(
                "ok",
                Map.of("matchCount", 1),
                List.of(
                    new FindingDraft(
                        "SSH Login", "HIGH", "d", "e", "r",
                        MsfModuleCatalogService.stableCodeFor("auxiliary/scanner/ssh/ssh_login")))));

    ToolExecutionResult result =
        engine.runMany(
            target,
            List.of(
                "auxiliary/scanner/ssh/ssh_login",
                "auxiliary/scanner/ssh/ssh_enumusers"),
            Map.of(),
            ToolExecutionObserver.NOOP);

    assertThat(result.findings()).hasSize(1);
    assertThat(result.findings().get(0).severity()).isEqualTo("HIGH");
    @SuppressWarnings("unchecked")
    Map<String, Object> data = result.data();
    assertThat(((Map<String, Object>) data.get("modules"))).hasSize(2);
  }

  @Test
  void runManyRejectsBlankOrTooManyModules() {
    assertThatThrownBy(() -> engine.runMany(target, List.of(), Map.of(), ToolExecutionObserver.NOOP))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("至少选择");

    java.util.List<String> tooMany = new java.util.ArrayList<>();
    for (int i = 0; i < 30; i++) tooMany.add("auxiliary/scanner/ssh/ssh_login_" + i);
    assertThatThrownBy(() -> engine.runMany(target, tooMany, Map.of(), ToolExecutionObserver.NOOP))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("最多选择");
  }
}