package com.bachelor.toolbox.tool.zap;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.TargetPolicyService;
import com.bachelor.toolbox.tool.ToolExecutionObserver;
import com.bachelor.toolbox.tool.ToolExecutionResult;
import java.net.URI;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class ZapFuzzToolTests {
  private static final URI TARGET = URI.create("https://127.0.0.1:8443");

  private final TargetPolicyService policy = mock(TargetPolicyService.class);

  private AuthorizedTarget target() {
    AuthorizedTarget authorized = new AuthorizedTarget();
    authorized.setTargetValue(TARGET.toString());
    authorized.setAllowedPorts("8443");
    authorized.setEnabled(true);
    return authorized;
  }

  private ZapFuzzTool tool(ZapDaemon daemon) {
    when(policy.validatedHttpUri(any())).thenReturn(TARGET);
    return new ZapFuzzTool(policy, () -> daemon);
  }

  private ZapDaemon stub(String fuzzId, String fuzzStatus) {
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
        return "";
      }

      @Override
      public int spiderProgress(String taskId) {
        return 100;
      }

      @Override
      public void stopSpider(String taskId) {}

      @Override
      public String startActiveScan(URI target) {
        return "";
      }

      @Override
      public int activeScanProgress(String scanId) {
        return 100;
      }

      @Override
      public void stopActiveScan(String scanId) {}

      @Override
      public List<ZapAlert> alerts() {
        return List.of();
      }

      @Override
      public void kill() {}

      @Override
      public void close() {}

      @Override
      public String startFuzz(FuzzSpec spec) {
        return fuzzId;
      }

      @Override
      public String fuzzStatus(String id) {
        return fuzzStatus;
      }
    };
  }

  @Test
  void fuzzesWithinScopeAndFoldsAlertsIntoFindings() throws Exception {
    ZapDaemon daemon =
        stub(
            "9",
            "stopped;id=9");
    ToolExecutionResult result =
        tool(daemon)
            .execute(
                target(),
                Map.of("fuzzTargetField", "id", "fuzzPayload", "1"), ToolExecutionObserver.NOOP);

    assertThat(result.findings()).isEmpty();
    assertThat(result.data()).containsEntry("matchCount", 0);
  }

  @Test
  void missingParametersDegradeToEmptyResult() throws Exception {
    ZapDaemon daemon = stub("", "notSupported");
    ToolExecutionResult result =
        tool(daemon).execute(target(), Map.of(), ToolExecutionObserver.NOOP);

    assertThat(result.findings()).isEmpty();
    assertThat(String.valueOf(result.summary())).contains("缺少");
  }
}