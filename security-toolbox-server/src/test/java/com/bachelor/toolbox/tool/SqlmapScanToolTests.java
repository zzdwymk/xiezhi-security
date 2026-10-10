package com.bachelor.toolbox.tool;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.dependency.ExecutableLocator;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.PortRangeParser;
import com.bachelor.toolbox.target.TargetPolicyService;
import com.bachelor.toolbox.target.WebTargetResolver;
import java.io.ByteArrayInputStream;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.InOrder;

class SqlmapScanToolTests {
  private final SqlmapScanTool tool =
      new SqlmapScanTool(
          new TargetPolicyService(false, new PortRangeParser()),
          mock(ExecutableLocator.class),
          "sqlmap",
          60);
  private static final String ENDING = "\n[*] ending @ 16:20:00 /2026-10-02/\n";
  private static final String NEGATIVE =
      "[16:19:59] [CRITICAL] all tested parameters do not appear to be injectable. "
          + "Try to increase values for '--level'/'--risk' options.";

  @Test
  void parsesConfirmedInjectionIntoFindings() {
    String output =
        """

        [INFO] testing connection to the target URL
        [WARNING] the back-end DBMS is MySQL
        [INFO] confirming SQL injection on the specified URL
        sqlmap identified the following injection point(s) with a total of 1 HTTP(s) request:
        ---
        Parameter: id (GET)
            Type: boolean-based blind
            Title: AND boolean-based blind - WHERE or HAVING clause
        Type: time-based blind
            Title: MySQL >= 5.0.12 AND time-based blind (comment)
        ---
        [INFO] the back-end DBMS is MySQL
        [INFO] fetched data logged to text files under
        [*] ending @ 16:20:00 /2026-10-02/
        """;

    ToolExecutionResult result = tool.parseOutput("http://10.0.0.1/less?id=1", output);

    assertThat(result.data()).containsEntry("vulnerable", true);
    assertThat(result.data()).containsEntry("parameter", "id (GET)");
    assertThat(result.findings()).hasSize(1);
    assertThat(result.findings().get(0).title()).isEqualTo("SQL 注入漏洞 · GET 参数 id");
    assertThat(result.findings().get(0).vulnerabilityCode()).isEqualTo("STB-SQLMAP-001");
    assertThat(result.findings().get(0).severity()).isEqualTo("HIGH");
  }

  @Test
  void acceptsSqlmapNormalCriticalNegativeConclusion() {
    ToolExecutionResult result = tool.parseOutput("http://127.0.0.1/page", NEGATIVE + ENDING);

    assertThat(result.data()).containsEntry("vulnerable", false);
    assertThat(result.findings()).isEmpty();
  }

  @ParameterizedTest
  @NullAndEmptySource
  @ValueSource(strings = {
    "[INFO] testing connection to the target URL",
    "[CRITICAL] all tested parameters do not appear to be injectable",
    "[INFO] shutting down\n[*] ending @ 16:20:00 /2026-10-02/"
  })
  void rejectsMissingOrIncompleteConclusion(String output) {
    assertThatThrownBy(() -> tool.parseOutput("http://127.0.0.1/page", output))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("无法判断");
  }

  @ParameterizedTest
  @ValueSource(strings = {
    "[16:20:00] [ERROR] unable to connect to the target URL",
    "[CRITICAL] connection timed out",
    "[CRITICAL] no parameter(s) found for testing in the provided data",
    "Traceback (most recent call last):"
  })
  void rejectsRuntimeErrorsEvenWhenNormalNegativeConclusionAlsoExists(String error) {
    assertThatThrownBy(() -> tool.parseOutput("http://127.0.0.1/page", NEGATIVE + "\n" + error + ENDING))
        .isInstanceOf(ApiException.class);
  }

  @ParameterizedTest
  @ValueSource(ints = {1, 2, -1})
  void rejectsNonZeroExitEvenWhenOutputContainsNormalNegativeConclusion(int exitCode) {
    assertThatThrownBy(() -> tool.parseOutput("http://127.0.0.1/page", NEGATIVE + ENDING, exitCode))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("退出码 " + exitCode);
  }

  @Test
  void validatesResolvedPortWithoutRequiringUnauthorizedDefaultPort() {
    AuthorizedTarget target = target("127.0.0.1", "8080,8443");
    Map<String, Object> parameters = resolvedBase("http://127.0.0.1:8080/");

    assertThat(tool.resolveTarget(target, parameters, "/Less-1/?id=1").toString())
        .isEqualTo("http://127.0.0.1:8080/Less-1/?id=1");
    assertThat(tool.resolveTarget(target, parameters, "https://127.0.0.1:8443/Less-1/?id=1").toString())
        .isEqualTo("https://127.0.0.1:8443/Less-1/?id=1");
  }

  @Test
  void rejectsAbsolutePathOutsideAuthorizedHostDespiteResolvedBase() {
    assertThatThrownBy(() -> tool.resolveTarget(
            target("127.0.0.1", "8080"), resolvedBase("http://127.0.0.1:8080/"),
            "http://127.0.0.2:8080/Less-1/?id=1"))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("主机");
  }

  @Test
  void rejectsAbsolutePathOutsideAuthorizedPortDespiteResolvedBase() {
    assertThatThrownBy(() -> tool.resolveTarget(
            target("127.0.0.1", "8080"), resolvedBase("http://127.0.0.1:8080/"),
            "http://127.0.0.1:9090/Less-1/?id=1"))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("授权端口");
  }

  @ParameterizedTest
  @ValueSource(strings = {
    "http://127.0.0.2:8080/",
    "http://127.0.0.1:9090/",
    "http://127.0.0.1:0/",
    "file:///tmp/test"
  })
  void revalidatesInternalResolvedBase(String base) {
    assertThatThrownBy(() -> tool.resolveTarget(
            target("127.0.0.1", "8080"), resolvedBase(base), ""))
        .isInstanceOf(ApiException.class);
  }

  @ParameterizedTest
  @ValueSource(strings = {
    "http://[invalid",
    "ftp://127.0.0.1:8080/test",
    "//127.0.0.2:8080/test",
    "http://admin:secret@127.0.0.1:8080/test",
    "http://127.0.0.1:8080/test#fragment"
  })
  void rejectsMalformedOrAmbiguousUrlWithoutFallingBackToBase(String path) {
    assertThatThrownBy(() -> tool.resolveTarget(
            target("127.0.0.1", "8080"), resolvedBase("http://127.0.0.1:8080/"), path))
        .isInstanceOf(ApiException.class);
  }

  @Test
  void disabledTargetCannotUseResolvedBase() {
    AuthorizedTarget target = target("127.0.0.1", "8080");
    target.setEnabled(false);
    assertThatThrownBy(() -> tool.resolveTarget(target, resolvedBase("http://127.0.0.1:8080/"), ""))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("停用");
  }

  @Test
  void keepsPolicyValidationWhenNoResolvedBaseIsPresent() {
    assertThat(tool.resolveTarget(target("http://127.0.0.1:8080/", "8080"), Map.of(), "/page?id=1").toString())
        .isEqualTo("http://127.0.0.1:8080/page?id=1");
    assertThatThrownBy(() -> tool.resolveTarget(
            target("http://127.0.0.1:8080/", "8080"), Map.of(), "http://127.0.0.2:8080/page?id=1"))
        .isInstanceOf(ApiException.class);
  }

  @Test
  void timeoutStopsProcessAndCannotReturnNegativeResult() throws Exception {
    Process process = unfinishedProcess();

    assertThatThrownBy(() -> tool.waitForProcess(process, ToolExecutionObserver.NOOP, 0, null))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("强制终止");
    verify(process).destroyForcibly();
  }

  @Test
  void cancellationStopsProcessAndCannotReturnNegativeResult() throws Exception {
    Process process = unfinishedProcess();
    ToolExecutionObserver observer = mock(ToolExecutionObserver.class);
    when(observer.isCancellationRequested()).thenReturn(true);

    assertThatThrownBy(() -> tool.waitForProcess(process, observer, 60, null))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("取消");
    verify(process).destroyForcibly();
  }

  @ParameterizedTest
  @ValueSource(booleans = {false, true})
  void stopsPythonDescendantsBeforeWindowsWrapperOnTimeoutOrCancellation(boolean cancelled)
      throws Exception {
    Process process = unfinishedProcess();
    ProcessHandle python = mock(ProcessHandle.class);
    ProcessHandle child = mock(ProcessHandle.class);
    when(process.descendants()).thenAnswer(invocation -> Stream.of(python, child));
    ToolExecutionObserver observer = mock(ToolExecutionObserver.class);
    when(observer.isCancellationRequested()).thenReturn(cancelled);

    assertThatThrownBy(() -> tool.waitForProcess(process, observer, 0, null))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining(cancelled ? "取消" : "强制终止");
    InOrder termination = inOrder(child, python, process);
    termination.verify(child).destroyForcibly();
    termination.verify(python).destroyForcibly();
    termination.verify(process).destroyForcibly();
  }

  private Process unfinishedProcess() throws Exception {
    Process process = mock(Process.class);
    when(process.getInputStream()).thenReturn(new ByteArrayInputStream(new byte[0]));
    when(process.waitFor(250, TimeUnit.MILLISECONDS)).thenReturn(false);
    when(process.waitFor(5, TimeUnit.SECONDS)).thenReturn(true);
    return process;
  }

  private AuthorizedTarget target(String value, String ports) {
    AuthorizedTarget target = new AuthorizedTarget();
    target.setTargetValue(value);
    target.setAllowedPorts(ports);
    return target;
  }

  private Map<String, Object> resolvedBase(String base) {
    return Map.of(WebTargetResolver.PARAM_RESOLVED_BASES, List.of(base));
  }
}
