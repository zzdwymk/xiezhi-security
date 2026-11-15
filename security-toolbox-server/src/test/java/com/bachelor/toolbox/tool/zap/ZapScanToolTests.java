package com.bachelor.toolbox.tool.zap;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.doThrow;
import static org.mockito.ArgumentMatchers.anyString;

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
      public long passiveScanRemaining() { return 0; }

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
                    "https://127.0.0.1:8443/login", "SQL Injection", "Medium", "Medium", null, "desc", 0),
                new ZapDaemon.ZapAlert(
                    "https://127.0.0.1:8443/", "XSS", "High", "High", "CWE-79", "desc", 1),
                new ZapDaemon.ZapAlert(
                    "https://192.0.2.10:8443/evil", "OutOfScope", "Critical", "High", "CWE-1", "desc", 1)));

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
                    "https://127.0.0.1:8443/a", "Low risk", "Medium (Medium)", "Confirmed", "CWE-200", "x", 0)));

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
  void disabledSpiderSeedsOnlySelectedUrlAndForwardsLowStrengthWithoutRecursion() throws Exception {
    ZapDaemon daemon = mock(ZapDaemon.class);
    when(daemon.startActiveScan(TARGET, null, "LOW", false)).thenReturn("850");
    when(daemon.activeScanProgress("850")).thenReturn(100);
    when(daemon.alerts()).thenReturn(List.of());
    when(daemon.crawlResults(TARGET)).thenReturn(List.of());
    when(daemon.technologies(TARGET)).thenReturn(List.of());

    tool(daemon).execute(target(), Map.of("spider", false, "strength", "LOW"));

    var order = inOrder(daemon);
    order.verify(daemon).includeInScope(TARGET);
    order.verify(daemon).accessUrl(TARGET);
    order.verify(daemon).startActiveScan(TARGET, null, "LOW", false);
    verify(daemon, never()).startSpider(any());
    verify(daemon, never()).startAjaxSpider(any());
  }

  @Test
  void missingScanIdStopsBeforePollingAnUnstartedScan() throws Exception {
    ZapDaemon daemon = mock(ZapDaemon.class);
    when(daemon.crawlResults(TARGET)).thenReturn(List.of());
    when(daemon.technologies(TARGET)).thenReturn(List.of());
    when(daemon.startActiveScan(TARGET, null, "LOW", false)).thenReturn("");

    assertThatThrownBy(() -> tool(daemon).execute(target(), Map.of("spider", false, "strength", "LOW")))
        .isInstanceOf(ApiException.class).hasMessageContaining("扫描未启动");
    verify(daemon, never()).activeScanProgress(anyString());
  }

  @Test
  void unavailableTargetStopsBeforeSpiderOrActiveScan() throws Exception {
    ZapDaemon daemon = mock(ZapDaemon.class);
    doThrow(new ApiException("未收到目标网站的有效响应")).when(daemon).accessUrl(TARGET);

    assertThatThrownBy(() -> tool(daemon).execute(target(), Map.of()))
        .hasMessageContaining("未收到目标网站的有效响应");
    verify(daemon, never()).startSpider(any());
    verify(daemon, never()).startActiveScan(any(), any(), any(), org.mockito.ArgumentMatchers.anyBoolean());
    verify(daemon, never()).alerts();
  }

  @Test
  void spiderConnectionFailureCannotReturnAnEmptySuccessfulResult() throws Exception {
    ZapDaemon daemon = mock(ZapDaemon.class);
    when(daemon.startSpider(TARGET)).thenReturn("1");
    when(daemon.spiderProgress("1")).thenThrow(new java.io.IOException("connection reset"));

    assertThatThrownBy(() -> tool(daemon).execute(target(), Map.of("mode", "passive")))
        .hasMessageContaining("执行失败");
    verify(daemon, never()).alerts();
  }

  @Test
  void waitsForPassiveChecksBeforeReadingEmptyAlerts() throws Exception {
    ZapDaemon daemon = mock(ZapDaemon.class);
    when(daemon.startActiveScan(TARGET, null, "MEDIUM", false)).thenReturn("1");
    when(daemon.activeScanProgress("1")).thenReturn(100);
    when(daemon.passiveScanRemaining()).thenReturn(1L, 0L);
    when(daemon.alerts()).thenReturn(List.of());

    tool(daemon).execute(target(), Map.of("spider", false));

    var order = inOrder(daemon);
    order.verify(daemon, org.mockito.Mockito.times(2)).passiveScanRemaining();
    order.verify(daemon).alerts();
  }

  @Test
  void unsupportedAjaxSpiderCannotBeReportedAsCompleted() throws Exception {
    ZapDaemon daemon = mock(ZapDaemon.class);
    when(daemon.startSpider(TARGET)).thenReturn("1");
    when(daemon.spiderProgress("1")).thenReturn(100);
    when(daemon.ajaxSpiderState()).thenReturn("notSupported");

    assertThatThrownBy(() -> tool(daemon).execute(target(), Map.of("ajaxSpider", true)))
        .hasMessageContaining("无法确认检测是否完成");
    verify(daemon, never()).alerts();
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

  @Test
  void zapUrlScopeCheckRejectsForeignHostsAndPorts() {
    // Round 113：openApiUrl/authLoginUrl 经规则路径用户可控（ActiveScanService toolParams 合并），
    // ZAP 会 GET/POST 该 URL —— 必须强制归属授权目标（防经 ZAP 的 SSRF）。
    ZapScanTool tool = tool(mock(ZapDaemon.class));
    AuthorizedTarget authorized = target();
    when(policy.validatedHost(authorized)).thenReturn("127.0.0.1");

    // 同目标同端口 → 通过
    tool.assertZapUrlWithinScope("https://127.0.0.1:8443/openapi.json", authorized);
    // 跨主机（元数据服务）→ 拒绝
    assertThatThrownBy(
            () ->
                tool.assertZapUrlWithinScope(
                    "http://169.254.169.254/latest/meta-data/", authorized))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("不在授权目标范围内");
    // 同主机不同端口（未授权端口）→ 拒绝（policy.validateAuthorizedPort 打桩抛出）
    doThrow(new ApiException("fscan 请求端口超出目标授权端口范围"))
        .when(policy)
        .validateAuthorizedPort(authorized, 9999);
    assertThatThrownBy(() -> tool.assertZapUrlWithinScope("https://127.0.0.1:9999/x", authorized))
        .isInstanceOf(ApiException.class);
    // 非 http/https 协议 → 拒绝
    assertThatThrownBy(() -> tool.assertZapUrlWithinScope("ftp://127.0.0.1/x", authorized))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("仅支持 http/https");
    // 用户信息 → 拒绝
    assertThatThrownBy(() -> tool.assertZapUrlWithinScope("http://user:secret@127.0.0.1:8443/x", authorized))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("不允许包含用户信息");
  }
}
