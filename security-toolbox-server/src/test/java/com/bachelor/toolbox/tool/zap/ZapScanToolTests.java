package com.bachelor.toolbox.tool.zap;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.TargetPolicyService;
import com.bachelor.toolbox.tool.ToolExecutionObserver;
import com.bachelor.toolbox.tool.ToolExecutionResult;
import java.net.URI;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class ZapScanToolTests {
  private static final URI TARGET = URI.create("https://127.0.0.1:8443");

  private final TargetPolicyService policy = mock(TargetPolicyService.class);

  private AuthorizedTarget target() {
    AuthorizedTarget authorized = new AuthorizedTarget();
    authorized.setTargetValue(TARGET.toString());
    authorized.setAllowedPorts("8443,80,443,8080,3000");
    authorized.setEnabled(true);
    return authorized;
  }

  private ZapScanTool tool(ZapDaemon daemon) {
    when(policy.validatedHttpUri(any())).thenReturn(TARGET);
    return new ZapScanTool(policy, () -> daemon, 60);
  }

  private ZapDaemon stubThatReachesDone(List<ZapDaemon.ZapAlert> alerts) {
    return new ZapDaemon() {
      @Override
      public boolean isReady() {
        return true;
      }

      @Override
      public void start() {}

      @Override
      public void includeInScope(URI target) {}

      @Override
      public String startSpider(URI target) {
        return "3";
      }

      @Override
      public int spiderProgress(String taskId) {
        return 100;
      }

      @Override
      public void stopSpider(String taskId) {}

      @Override
      public String startActiveScan(URI target) {
        return "7";
      }

      @Override
      public int activeScanProgress(String scanId) {
        return 100;
      }

      @Override
      public void stopActiveScan(String scanId) {}

      @Override
      public List<ZapDaemon.ZapAlert> alerts() {
        return alerts;
      }

      @Override
      public void kill() {}

      @Override
      public void close() {}
    };
  }

  @Test
  void mapsInScopeAlertsIntoFindingsAndFiltersOutOfScope() throws Exception {
    ZapDaemon daemon =
        stubThatReachesDone(
            List.of(
                new ZapDaemon.ZapAlert(
                    "https://127.0.0.1:8443/login", "SQL Injection", "Medium", "Medium", null, "desc"),
                new ZapDaemon.ZapAlert(
                    "https://127.0.0.1:8443/", "XSS", "High", "High", "CWE-79", "desc"),
                new ZapDaemon.ZapAlert(
                    "https://192.0.2.10:8443/evil", "OutOfScope", "Critical", "High", "CWE-1", "desc")));

    ToolExecutionResult result = tool(daemon).execute(target(), Map.of(), ToolExecutionObserver.NOOP);

    assertThat(result.findings()).hasSize(2);
    assertThat(result.findings())
        .extracting(f -> f.title())
        .containsExactlyInAnyOrder("SQL Injection", "XSS");
    assertThat(result.findings())
        .anySatisfy(
            f -> {
              assertThat(f.severity()).isEqualTo("HIGH");
              assertThat(f.vulnerabilityCode()).isEqualTo("CWE-79");
            });
    assertThat(result.data()).containsEntry("matchCount", 2).containsEntry("inScopeAlertCount", 2);
  }

  @Test
  void normalizesSeverityFromZapRiskDescriptions() throws Exception {
    ZapDaemon daemon =
        stubThatReachesDone(
            List.of(
                new ZapDaemon.ZapAlert(
                    "https://127.0.0.1:8443/a", "Low risk", "Medium (Medium)", "Confirmed", "CWE-200", "x")));

    ToolExecutionResult result = tool(daemon).execute(target(), Map.of(), ToolExecutionObserver.NOOP);

    assertThat(result.findings()).hasSize(1);
    assertThat(result.findings().get(0).severity()).isEqualTo("MEDIUM");
  }

  @Test
  void validatesAttackStrengthParameter() {
    ZapDaemon daemon = stubThatReachesDone(List.of());

    assertThatThrownBy(() -> tool(daemon).execute(target(), Map.of("strength", "cosmic"), ToolExecutionObserver.NOOP))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("不支持的 ZAP 攻击强度");
  }

  @Test
  void propagatesCancellation() {
    ZapDaemon daemon =
        new ZapDaemon() {
          private int calls;

          @Override
          public boolean isReady() {
            return true;
          }

          @Override
          public void start() {}

          @Override
          public void includeInScope(URI target) {}

          @Override
          public String startSpider(URI target) {
            return "1";
          }

          @Override
          public int spiderProgress(String taskId) {
            return 50;
          }

          @Override
          public void stopSpider(String taskId) {}

          @Override
          public String startActiveScan(URI target) {
            return "2";
          }

          @Override
          public int activeScanProgress(String scanId) {
            calls++;
            return 40;
          }

          @Override
          public void stopActiveScan(String scanId) {}

          @Override
          public List<ZapDaemon.ZapAlert> alerts() {
            return List.of();
          }

          @Override
          public void kill() {}

          @Override
          public void close() {}
        };

    assertThatThrownBy(
            () ->
                tool(daemon)
                    .execute(
                        target(),
                        Map.of("spider", false),
                        new ToolExecutionObserver() {
                          @Override
                          public boolean isCancellationRequested() {
                            return true;
                          }
                        }))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("任务已取消");
  }
}