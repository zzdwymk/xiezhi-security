package com.bachelor.toolbox.tool.zap;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.PortRangeParser;
import com.bachelor.toolbox.target.TargetPolicyService;
import com.bachelor.toolbox.tool.ToolExecutionObserver;
import com.bachelor.toolbox.tool.ToolExecutionResult;
import java.net.URI;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;

class ZapFuzzToolTests {
  private final ZapDaemon daemon = mock(ZapDaemon.class);
  private final ZapFuzzTool tool = new ZapFuzzTool(
      new TargetPolicyService(false, new PortRangeParser()), () -> daemon);

  private AuthorizedTarget target() {
    AuthorizedTarget target = new AuthorizedTarget();
    target.setTargetValue("127.0.0.1");
    target.setAllowedPorts("8443");
    return target;
  }

  private Map<String, Object> parameters() {
    return new LinkedHashMap<>(Map.of("fuzzRequestUrl", "https://127.0.0.1:8443/form",
        "method", "POST", "fuzzPostBody", "keep=one&id=original",
        "fuzzPayload", " a&b ", "fuzzTargetField", "id"));
  }

  @Test
  void sendsOneLiteralMutationAndReportsOnlyInScopePassiveAlerts() throws Exception {
    when(daemon.startFuzz(any())).thenReturn("request-9");
    when(daemon.fuzzStatus("request-9")).thenReturn("stopped;id=request-9;requests=1");
    when(daemon.alerts()).thenReturn(List.of(
        new ZapDaemon.ZapAlert("https://127.0.0.1:8443/form", "Header", "LOW", "HIGH", "16", "missing", 1),
        new ZapDaemon.ZapAlert("https://127.0.0.2:8443/form", "Other", "HIGH", "HIGH", "79", "other", 1)));
    Map<String, Object> values = parameters(); values.remove("method");
    ToolExecutionResult result = tool.execute(target(), values);
    ArgumentCaptor<ZapDaemon.FuzzSpec> spec = ArgumentCaptor.forClass(ZapDaemon.FuzzSpec.class);
    verify(daemon).startFuzz(spec.capture());
    assertThat(spec.getValue().method()).isEqualTo("POST");
    assertThat(spec.getValue().payload()).isEqualTo(" a&b ");
    assertThat(spec.getValue().requestMessage()).endsWith("keep=one&id=+a%26b+");
    assertThat(result.data()).containsEntry("requestCount", 1).containsEntry("mode", "SINGLE_PARAMETER_MUTATION");
    assertThat(result.findings()).hasSize(1);
    assertThat(result.summary()).contains("单次参数变异", "被动告警");
    verify(daemon).close();
  }

  @Test
  void ignoresInternalResolvedBasesWhenExplicitRequestUrlIsAuthorized() throws Exception {
    when(daemon.startFuzz(any())).thenReturn("request-9");
    when(daemon.fuzzStatus("request-9")).thenReturn("stopped;id=request-9;requests=1");
    when(daemon.alerts()).thenReturn(List.of());
    Map<String, Object> values = parameters();
    values.put("__resolvedWebBases", List.of("http://127.0.0.2:9443/"));
    tool.execute(target(), values);
    ArgumentCaptor<ZapDaemon.FuzzSpec> spec = ArgumentCaptor.forClass(ZapDaemon.FuzzSpec.class);
    verify(daemon).startFuzz(spec.capture());
    assertThat(spec.getValue().requestUrl()).isEqualTo("https://127.0.0.1:8443/form");
  }

  @ParameterizedTest
  @ValueSource(strings = {"fuzzRequestUrl", "fuzzPayload", "fuzzTargetField"})
  void missingRequiredParameterFailsBeforeDaemonStarts(String key) {
    Map<String, Object> values = parameters(); values.remove(key);
    assertThatThrownBy(() -> tool.execute(target(), values)).isInstanceOf(ApiException.class);
    verifyNoInteractions(daemon);
  }

  @ParameterizedTest
  @ValueSource(strings = {"http://127.0.0.2:8443/form", "https://127.0.0.1:9443/form",
      "https://admin:password@127.0.0.1:8443/form", "file:///tmp/form",
      "https://127.0.0.1:8443/form#fragment", "//127.0.0.1:8443/form"})
  void outOfScopeOrAmbiguousUrlFailsBeforeDaemonStarts(String url) {
    Map<String, Object> values = parameters(); values.put("fuzzRequestUrl", url);
    assertThatThrownBy(() -> tool.execute(target(), values)).isInstanceOf(ApiException.class);
    verifyNoInteractions(daemon);
  }

  @ParameterizedTest
  @ValueSource(strings = {"missing=1", "id=one&id=two", "id=one&%69d=two", "id=one&bad=%ZZ"})
  void missingDuplicateOrMalformedFormFieldFailsBeforeDaemonStarts(String body) {
    Map<String, Object> values = parameters(); values.put("fuzzPostBody", body);
    assertThatThrownBy(() -> tool.execute(target(), values)).isInstanceOf(ApiException.class);
    verifyNoInteractions(daemon);
  }

  @Test
  void rejectsUnknownAndNonStringParametersWithoutStartingDaemon() {
    Map<String, Object> values = parameters(); values.put("script", "/tmp/unapproved.js");
    assertThatThrownBy(() -> tool.execute(target(), values)).isInstanceOf(ApiException.class);
    values.remove("script"); values.put("fuzzPayload", List.of("one", "two"));
    assertThatThrownBy(() -> tool.execute(target(), values)).isInstanceOf(ApiException.class);
    verifyNoInteractions(daemon);
  }

  @ParameterizedTest
  @NullAndEmptySource
  @ValueSource(strings = {"notSupported", "notstopped", "stopped=false", "failed"})
  void unknownStatusCannotBecomeSuccessfulResult(String state) throws Exception {
    when(daemon.startFuzz(any())).thenReturn("request-9");
    when(daemon.fuzzStatus("request-9")).thenReturn(state);
    assertThatThrownBy(() -> tool.execute(target(), parameters())).isInstanceOf(ApiException.class);
    verify(daemon, never()).alerts(); verify(daemon).kill(); verify(daemon).close();
  }

  @ParameterizedTest
  @NullAndEmptySource
  void emptyStartReceiptFailsAndClosesDaemon(String id) throws Exception {
    when(daemon.startFuzz(any())).thenReturn(id);
    assertThatThrownBy(() -> tool.execute(target(), parameters())).isInstanceOf(ApiException.class);
    verify(daemon, never()).fuzzStatus(any()); verify(daemon, never()).alerts(); verify(daemon).kill();
  }

  @Test
  void expiredDeadlineCannotBecomeSuccessfulResult() throws Exception {
    assertThatThrownBy(() -> tool.awaitCompletion(daemon, "request-9", ToolExecutionObserver.NOOP, 0))
        .isInstanceOf(ApiException.class).hasMessageContaining("超时");
    verifyNoInteractions(daemon);
  }

  @Test
  void cancellationBeforeExecutionDoesNotStartDaemon() {
    ToolExecutionObserver observer = mock(ToolExecutionObserver.class);
    when(observer.isCancellationRequested()).thenReturn(true);
    assertThatThrownBy(() -> tool.execute(target(), parameters(), observer))
        .isInstanceOf(ApiException.class).hasMessageContaining("取消");
    verifyNoInteractions(daemon);
  }

  @Test
  void cancellationWhileWaitingKillsDaemonWithoutReadingAlerts() throws Exception {
    when(daemon.startFuzz(any())).thenReturn("request-9");
    ToolExecutionObserver observer = mock(ToolExecutionObserver.class);
    when(observer.isCancellationRequested()).thenReturn(false, false, true);
    assertThatThrownBy(() -> tool.execute(target(), parameters(), observer))
        .isInstanceOf(ApiException.class).hasMessageContaining("取消");
    verify(daemon).kill(); verify(daemon, never()).alerts();
  }

  @ParameterizedTest
  @ValueSource(strings = {"get", "DELETE", "POST\r\nInjected: yes"})
  void methodMustBeExactGetOrPost(String method) {
    Map<String, Object> values = parameters(); values.put("method", method);
    assertThatThrownBy(() -> tool.execute(target(), values)).isInstanceOf(ApiException.class);
    verifyNoInteractions(daemon);
  }

  @Test
  void validatesLengthAndControlCharacterLimitsBeforeExecution() {
    for (Map.Entry<String, Object> invalid : Map.<String, Object>of(
        "fuzzPostBody", "x".repeat(4001), "fuzzPayload", "x".repeat(1001),
        "fuzzTargetField", "x".repeat(129)).entrySet()) {
      Map<String, Object> values = parameters(); values.put(invalid.getKey(), invalid.getValue());
      assertThatThrownBy(() -> tool.execute(target(), values)).isInstanceOf(ApiException.class);
    }
    for (String key : List.of("fuzzPayload", "fuzzPostBody", "fuzzTargetField")) {
      Map<String, Object> values = parameters(); values.put(key, "id\r\ninjected");
      assertThatThrownBy(() -> tool.execute(target(), values)).isInstanceOf(ApiException.class);
    }
    verifyNoInteractions(daemon);
  }

  @Test
  void getMutationHasNoBodyAndTreatsFileLikePayloadAsLiteral() {
    URI uri = URI.create("https://127.0.0.1:8443/form?keep=one&id=old");
    ZapDaemon.FuzzSpec spec = new ZapDaemon.FuzzSpec(uri, uri.toString(), "GET", "", "file:///tmp/a", "id");
    assertThat(spec.requestMessage()).startsWith("GET https://127.0.0.1:8443/form?keep=one&id=file%3A%2F%2F%2Ftmp%2Fa HTTP/1.1")
        .doesNotContain("Content-Type:", "Content-Length:").endsWith("\r\n\r\n");
    assertThatThrownBy(() -> new ZapDaemon.FuzzSpec(uri, uri.toString(), "GET", "id=old", "test", "id"))
        .isInstanceOf(ApiException.class);
  }
}
