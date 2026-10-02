package com.bachelor.toolbox.msf;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.times;

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
    assertThatThrownBy(() -> engine.runMany(target, List.of(), Map.of(), Map.of(), ToolExecutionObserver.NOOP))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("至少选择");

    java.util.List<String> tooMany = new java.util.ArrayList<>();
    for (int i = 0; i < 5001; i++) tooMany.add("auxiliary/scanner/ssh/ssh_login_" + i);
    assertThatThrownBy(() -> engine.runMany(target, tooMany, Map.of(), Map.of(), ToolExecutionObserver.NOOP))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("最多选择");
  }

  @Test
  void propagatesSingleModuleTimeoutInsteadOfReturningEmptySuccess() throws Exception {
    var timeout = new java.util.concurrent.TimeoutException("执行超过 600 秒");
    when(tool.execute(any(), any(), any(ToolExecutionObserver.class))).thenThrow(timeout);
    assertThatThrownBy(() -> engine.runMany(target, List.of("auxiliary/scanner/http/http_header"),
        Map.of(), Map.of(), ToolExecutionObserver.NOOP))
        .isInstanceOf(ApiException.class).hasCause(timeout).hasMessageContaining("已完成 0/1");
  }

  @Test
  void keepsRawHeaderObservationsWhenAggregatingWithoutCreatingFindings() throws Exception {
    String module = "auxiliary/scanner/http/http_header";
    Map<String, Object> observed = Map.of("matchCount", 0, "observations",
        List.of(Map.of("message", "127.0.0.1:80 SERVER: nginx", "vulnerability", false)));
    when(tool.execute(any(), any(), any(ToolExecutionObserver.class)))
        .thenReturn(new ToolExecutionResult("响应头读取完成", observed, List.of()));
    var result = engine.runMany(target, List.of(module), Map.of(), Map.of(), ToolExecutionObserver.NOOP);
    assertThat(result.findings()).isEmpty();
    Map<?, ?> modules = (Map<?, ?>) result.data().get("modules");
    assertThat(((Map<?, ?>) modules.get(module)).get("result")).isEqualTo(observed);
  }

  @Test
  void partialFailureStopsRemainingModulesAndNeverReportsBatchSuccess() throws Exception {
    when(tool.execute(any(), any(), any(ToolExecutionObserver.class)))
        .thenReturn(new ToolExecutionResult("complete", Map.of("matchCount", 0), List.of()))
        .thenThrow(new ApiException("模块失败"));
    assertThatThrownBy(() -> engine.runMany(target,
        List.of("auxiliary/scanner/http/http_header", "auxiliary/scanner/http/http_version", "auxiliary/scanner/ssl/ssl_version"),
        Map.of(), Map.of(), ToolExecutionObserver.NOOP))
        .isInstanceOf(ApiException.class).hasMessageContaining("已完成 1/3").hasMessageContaining("后续未执行");
    verify(tool, times(2)).execute(any(), any(), any(ToolExecutionObserver.class));
  }
}
