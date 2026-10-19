package com.bachelor.toolbox.ai;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.common.ApiException;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.slf4j.LoggerFactory;

class RuntimeProtocolDiagnosticsTests {
  @ParameterizedTest
  @MethodSource("knownFailures")
  void distinguishesRuntimeTerminalFromJavaValidation(String message, String stage, String code) {
    var failure = RuntimeProtocolDiagnostics.classify(
        new AiAgentRuntimeClient.RuntimeProtocolException(message));
    assertThat(failure.stage().name()).isEqualTo(stage);
    assertThat(failure.code().name()).isEqualTo(code);
  }

  static Stream<Arguments> knownFailures() {
    return Stream.of(
        Arguments.of("AI Runtime 本轮未完成：ROUTE_FAILED", "RUNTIME_TERMINAL", "ROUTE_FAILED"),
        Arguments.of("AI Runtime 本轮未完成：GROUNDED_GENERATION_FAILED", "RUNTIME_TERMINAL", "GROUNDED_GENERATION_FAILED"),
        Arguments.of("AI Runtime 本轮未完成：GROUNDED_REFERENCE_INVALID", "RUNTIME_TERMINAL", "GROUNDED_REFERENCE_INVALID"),
        Arguments.of("AI Runtime 本轮未完成：EVIDENCE_ASSESSMENT_FAILED", "RUNTIME_TERMINAL", "EVIDENCE_ASSESSMENT_FAILED"),
        Arguments.of("AI Runtime 返回失败终态：TURN_TIMEOUT", "RUNTIME_TERMINAL", "TURN_TIMEOUT"),
        Arguments.of("AI Runtime 本轮未完成：MODEL_ACCESS_DENIED", "RUNTIME_TERMINAL", "MODEL_ACCESS_DENIED"),
        Arguments.of("AI Runtime 本轮未完成：MODEL_NOT_CONFIGURED", "RUNTIME_TERMINAL", "MODEL_NOT_CONFIGURED"),
        Arguments.of("AI Runtime 返回失败终态：MODEL_NOT_CONFIGURED", "RUNTIME_TERMINAL", "MODEL_NOT_CONFIGURED"),
        Arguments.of("AI Runtime 本轮未完成：MODEL_SERVICE_UNAVAILABLE", "RUNTIME_TERMINAL", "MODEL_SERVICE_UNAVAILABLE"),
        Arguments.of("AI Runtime 返回失败终态：MODEL_REQUEST_FAILED", "RUNTIME_TERMINAL", "MODEL_REQUEST_FAILED"),
        Arguments.of("AI Runtime 本轮未完成：MODEL_TIMEOUT", "RUNTIME_TERMINAL", "MODEL_TIMEOUT"),
        Arguments.of("AI Runtime 本轮未完成：UNKNOWN", "RUNTIME_TERMINAL", "UNKNOWN_RUNTIME_TERMINAL"),
        Arguments.of("AI Runtime 本轮未完成：MODEL_NOT_CONFIGURED extra", "RUNTIME_TERMINAL", "UNKNOWN_RUNTIME_TERMINAL"),
        Arguments.of("AI Runtime 返回失败终态：MODEL_NOT_CONFIGURED\\nEXFILTRATE", "RUNTIME_TERMINAL", "UNKNOWN_RUNTIME_TERMINAL"),
        Arguments.of("AI Runtime SQLMap 计划必须要求审批", "JAVA_SEMANTIC", "AUTHORIZATION_MISMATCH"),
        Arguments.of("AI Runtime 候选 Ledger 摘要链无效", "JAVA_LEDGER", "LEDGER_DIGEST_INVALID"),
        Arguments.of("Java Ledger 未完整持久化 Runtime 事件流", "JAVA_LEDGER", "LEDGER_PERSISTENCE_INVALID"),
        Arguments.of("AI Runtime route intent 与最终计划语义不一致", "JAVA_SEMANTIC", "ROUTE_PLAN_MISMATCH"),
        Arguments.of("AI Runtime AUTO route 缺少 executionDecision", "JAVA_SEMANTIC", "AUTO_DECISION_INVALID"),
        Arguments.of("AI Runtime plan 事件与终态计划不一致", "JAVA_SEMANTIC", "PLAN_EVENT_MISMATCH"),
        Arguments.of("AI Runtime 计划引用了当前 EvidenceBundle 之外的证据", "JAVA_SEMANTIC", "EVIDENCE_SCOPE_INVALID"),
        Arguments.of("AI Runtime 字段 executionDecision 格式无效", "JAVA_FIELDS", "FIELD_CONTRACT_INVALID"),
        Arguments.of("AI Runtime 计划 缺少字段 knowledgeMode", "JAVA_FIELDS", "FIELD_CONTRACT_INVALID"),
        Arguments.of("AI Runtime route data 包含未知字段", "JAVA_FIELDS", "FIELD_CONTRACT_INVALID"),
        Arguments.of("AI Runtime 事件不是合法 JSON", "JAVA_FIELDS", "EVENT_JSON_INVALID"),
        Arguments.of("AI Runtime 流在终态前中断", "JAVA_STREAM", "STREAM_INCOMPLETE"),
        Arguments.of("unrecognized internal failure", "JAVA_PROTOCOL", "UNKNOWN_PROTOCOL_FAILURE"));
  }

  @Test
  void modelProviderTerminalCodesAreNeverReportedAsIntegrityFailures() {
    // Regression: the runtime answers MODEL_NOT_CONFIGURED with a well-formed fail-closed turn,
    // so the operator must be told to configure the model — not that the response was corrupt.
    for (var message : List.of(
        "AI Runtime 本轮未完成：MODEL_NOT_CONFIGURED",
        "AI Runtime 返回失败终态：MODEL_NOT_CONFIGURED")) {
      var failure = RuntimeProtocolDiagnostics.classify(
          new AiAgentRuntimeClient.RuntimeProtocolException(message));
      assertThat(failure.stage()).isEqualTo(RuntimeProtocolDiagnostics.Stage.RUNTIME_TERMINAL);
      assertThat(failure.code()).isEqualTo(RuntimeProtocolDiagnostics.Code.MODEL_NOT_CONFIGURED);
      assertThat(RuntimeProtocolDiagnostics.userMessage(failure))
          .contains("AI 模型未配置或未启用", "系统设置", "尚未提交审批申请", "未创建检测任务", "未执行任何检测")
          .doesNotContain("完整性校验", "完整性", "检查模型连接");
    }
  }

  @ParameterizedTest
  @ValueSource(strings = {
      "AI Runtime 本轮未完成：MODEL_ACCESS_DENIED",
      "AI Runtime 本轮未完成：MODEL_RATE_LIMITED",
      "AI Runtime 返回失败终态：MODEL_TIMEOUT",
      "AI Runtime 返回失败终态：MODEL_SERVICE_UNAVAILABLE",
      "AI Runtime 本轮未完成：MODEL_REQUEST_FAILED",
      "AI Runtime 本轮未完成：TURN_TIMEOUT"
  })
  void everyRuntimeTerminalCodeExplainsTheActualCause(String message) {
    var failure = RuntimeProtocolDiagnostics.classify(
        new AiAgentRuntimeClient.RuntimeProtocolException(message));
    assertThat(failure.stage()).isEqualTo(RuntimeProtocolDiagnostics.Stage.RUNTIME_TERMINAL);
    assertThat(failure.code()).isNotIn(
        RuntimeProtocolDiagnostics.Code.UNKNOWN_PROTOCOL_FAILURE,
        RuntimeProtocolDiagnostics.Code.UNKNOWN_RUNTIME_TERMINAL);
    assertThat(RuntimeProtocolDiagnostics.userMessage(failure))
        .contains("本轮已安全停止", "尚未提交审批申请", "未创建检测任务", "未执行任何检测")
        .doesNotContain("完整性校验", "完整性");
  }

  @Test
  void nullMessageIsUnknown() {
    assertThat(RuntimeProtocolDiagnostics.classify(
        new AiAgentRuntimeClient.RuntimeProtocolException(null)).code())
        .isEqualTo(RuntimeProtocolDiagnostics.Code.UNKNOWN_PROTOCOL_FAILURE);
  }

  @Test
  void unknownProtocolFailureNoLongerBlamesTheModelConnection() {
    // Regression: JAVA_PROTOCOL failures were shown with "请检查模型连接后重试" even though the
    // model connection had been verified as healthy, misleading operators into reconnecting.
    var failure = RuntimeProtocolDiagnostics.classify(
        new AiAgentRuntimeClient.RuntimeProtocolException("unrecognized internal failure"));
    assertThat(failure.stage()).isEqualTo(RuntimeProtocolDiagnostics.Stage.JAVA_PROTOCOL);
    assertThat(RuntimeProtocolDiagnostics.userMessage(failure))
        .contains("完整性校验", "AI 诊断记录")
        .doesNotContain("检查模型连接");
  }

  @ParameterizedTest
  @ValueSource(strings = {
      "AI Runtime 计划包含未知工具",
      "AI Runtime 计划包含重复工作流节点",
      "AI Runtime 高风险工具计划必须要求审批",
      "AI Runtime action 风险或分组无效",
      "AI Runtime dir_scan concurrency 必须是整数",
      "AI Runtime 字段 extensions 类型无效",
      "AI Runtime tool status 无效",
      "AI Runtime 终态无效",
      "AI Runtime modelUsage source 无效",
      "AI Runtime knowledgeMode 无效"
  })
  void planAndFieldValidationFailuresAreClassifiedInsteadOfUnknown(String message) {
    // Regression: 122 of 172 validation templates fell into UNKNOWN_PROTOCOL_FAILURE, so real
    // plan-contract violations (e.g. a new tool or field mismatch) surfaced as a vague
    // "integrity check" error with no actionable cause.
    var failure = RuntimeProtocolDiagnostics.classify(
        new AiAgentRuntimeClient.RuntimeProtocolException(message));
    assertThat(failure.code()).isNotEqualTo(RuntimeProtocolDiagnostics.Code.UNKNOWN_PROTOCOL_FAILURE);
    assertThat(failure.stage()).isEqualTo(RuntimeProtocolDiagnostics.Stage.JAVA_FIELDS);
  }

  @ParameterizedTest
  @ValueSource(strings = {
      "AI Runtime 在 plan 之前发送 finish",
      "AI Runtime 检索链路在完成前进入 plan/finish",
      "AI Runtime 事件超过大小限制",
      "AI Runtime 生命周期阶段顺序无效"
  })
  void streamOrderFailuresMapToStreamStage(String message) {
    var failure = RuntimeProtocolDiagnostics.classify(
        new AiAgentRuntimeClient.RuntimeProtocolException(message));
    assertThat(failure.stage()).isEqualTo(RuntimeProtocolDiagnostics.Stage.JAVA_STREAM);
    assertThat(failure.code()).isEqualTo(RuntimeProtocolDiagnostics.Code.STREAM_INCOMPLETE);
  }

  @ParameterizedTest
  @ValueSource(strings = {
      "项目依据检索未返回完整结果",
      "项目依据字段 title 格式无效",
      "项目依据包含重复证据编号"
  })
  void evidenceRetrievalFailuresMapToRetrievalStage(String message) {
    var failure = RuntimeProtocolDiagnostics.classify(
        new AiAgentRuntimeClient.RuntimeProtocolException(message));
    assertThat(failure.stage()).isEqualTo(RuntimeProtocolDiagnostics.Stage.JAVA_SEMANTIC);
    assertThat(failure.code()).isEqualTo(RuntimeProtocolDiagnostics.Code.RETRIEVAL_FAILED);
  }

  @Test
  void harnessRejectionMapsToModelRequestFailure() {
    var failure = RuntimeProtocolDiagnostics.classify(
        new AiAgentRuntimeClient.RuntimeProtocolException("AI Runtime 拒绝了 Harness 请求（HTTP 403）"));
    assertThat(failure.code()).isEqualTo(RuntimeProtocolDiagnostics.Code.MODEL_REQUEST_FAILED);
    assertThat(RuntimeProtocolDiagnostics.userMessage(failure))
        .contains("模型服务拒绝了本次请求")
        .doesNotContain("完整性校验");
  }

  @ParameterizedTest
  @ValueSource(strings = {
      "AI Runtime 本轮未完成：GROUNDED_REFERENCE_INVALID",
      "AI Runtime 返回失败终态：GROUNDED_REFERENCE_INVALID"
  })
  void invalidGroundingReferenceReportsTheActualCauseWithoutWeakeningStop(String message) {
    var failure = RuntimeProtocolDiagnostics.classify(
        new AiAgentRuntimeClient.RuntimeProtocolException(message));
    assertThat(RuntimeProtocolDiagnostics.userMessage(failure))
        .contains("本轮证据中不存在的编号", "尚未提交审批申请", "未创建检测任务", "未执行任何检测")
        .doesNotContain("检查模型连接", "完整性与一致性检查", "Harness 协议校验");
  }

  @ParameterizedTest
  @ValueSource(strings = {
      "AI Runtime 本轮未完成：GROUNDED_GENERATION_FAILED",
      "AI Runtime 返回失败终态：GROUNDED_GENERATION_FAILED"
  })
  void groundedOutputFailureDoesNotMisdiagnoseTheModelConnection(String message) {
    var failure = RuntimeProtocolDiagnostics.classify(
        new AiAgentRuntimeClient.RuntimeProtocolException(message));
    assertThat(RuntimeProtocolDiagnostics.userMessage(failure))
        .contains("回答或检测方案", "完整性与一致性检查", "尚未提交审批申请", "未创建检测任务", "未执行任何检测")
        .doesNotContain("检查模型连接", "Harness 协议校验");
  }

  @ParameterizedTest
  @ValueSource(strings = {
      "AI Runtime 本轮未完成：EVIDENCE_ASSESSMENT_FAILED",
      "AI Runtime 返回失败终态：EVIDENCE_ASSESSMENT_FAILED"
  })
  void evidenceAssessmentFailureReportsItsStageAndNoApprovalOrExecution(String message) throws Exception {
    var tools = mock(SecurityAgentTools.class);
    var runtime = mock(AiAgentRuntimeClient.class);
    var planner = mock(AiPlanningService.class);
    var guard = mock(AiAuthorizationGuard.class);
    var reviewer = mock(AiExecutionReviewer.class);
    when(tools.inspectProjectContext(5L, 8L)).thenReturn("authorized context");
    when(runtime.enabled()).thenReturn(true);
    when(runtime.plan(any(), anyString(), any()))
        .thenThrow(new AiAgentRuntimeClient.RuntimeProtocolException(message));
    var orchestrator = new AgentOrchestrator(new AiConversationMemoryService(20, 20, 120),
        tools, runtime, mock(AiProjectIndexService.class), planner, guard, reviewer, mock(AuditService.class));
    var request = new AiAgentRequest(5L, 8L, "assessment-test", "扫描已授权目标", true,
        null, List.of(), "standard", "turn-assessment", "workflow-assessment", 1L,
        "sha256:" + "a".repeat(64), "ledger-agent", "node-assessment");

    assertThatThrownBy(() -> orchestrator.run(request))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("未能完成证据评估")
        .hasMessageContaining("尚未提交审批申请")
        .hasMessageContaining("未创建检测任务")
        .hasMessageNotContaining("Harness 协议校验")
        .hasMessageNotContaining("格式不完整");
    verifyNoInteractions(planner, guard, reviewer);
    verify(tools, never()).executeAuthorizedPlan(any(), any());
  }

  @ParameterizedTest
  @ValueSource(strings = {
      "AI Runtime 事件不是合法 JSON",
      "AI Runtime 流在终态前中断",
      "AI Runtime 字段 EVIDENCE_ASSESSMENT_FAILED 格式无效",
      "AI Runtime 字段 MODEL_TIMEOUT 格式无效"
  })
  void malformedResponseStillReportsProtocolValidationFailure(String message) {
    var failure = RuntimeProtocolDiagnostics.classify(
        new AiAgentRuntimeClient.RuntimeProtocolException(message));
    assertThat(RuntimeProtocolDiagnostics.userMessage(failure))
        .contains("返回内容未通过完整性校验", "尚未提交审批申请", "未创建检测任务")
        .doesNotContain("未能完成证据评估", "模型服务连接超时");
  }

  @Test
  void everyPublicFailureUsesChineseLabelsWhileClassificationKeepsItsCodes() {
    for (var stage : RuntimeProtocolDiagnostics.Stage.values()) {
      for (var code : RuntimeProtocolDiagnostics.Code.values()) {
        var failure = new RuntimeProtocolDiagnostics.Failure(stage, code);
        assertThat(RuntimeProtocolDiagnostics.userMessage(failure))
            .contains("本轮已安全停止")
            .doesNotContain("Runtime", "Harness", "Ledger", "Turn", stage.name(), code.name());
        assertThat(failure.stage()).isSameAs(stage);
        assertThat(failure.code()).isSameAs(code);
      }
    }
  }

  @ParameterizedTest
  @ValueSource(strings = {
      "model text contains sk-secret-EXFILTRATE\nforged log entry",
      "AI Runtime 本轮未完成：ROUTE_FAILED\nEXFILTRATE",
      "AI Runtime 返回失败终态：sk-secret-EXFILTRATE",
      "AI Runtime 字段 sk-secret-EXFILTRATE 格式无效",
      "AI Runtime EXFILTRATE 缺少字段 password",
      "AI Runtime route intent 与最终计划语义不一致"
  })
  void orchestratorLogsOnlyFiniteEnumsAndNeverMessageCauseOrRequest(String message) throws Exception {
    var tools = mock(SecurityAgentTools.class);
    var runtime = mock(AiAgentRuntimeClient.class);
    var planner = mock(AiPlanningService.class);
    var guard = mock(AiAuthorizationGuard.class);
    var reviewer = mock(AiExecutionReviewer.class);
    when(tools.inspectProjectContext(5L, 8L)).thenReturn("EXFILTRATE-context");
    when(runtime.enabled()).thenReturn(true);
    var exception = new AiAgentRuntimeClient.RuntimeProtocolException(
        message, new IllegalStateException("EXFILTRATE-cause"));
    exception.addSuppressed(new RuntimeException("EXFILTRATE-suppressed"));
    when(runtime.plan(any(), anyString(), any())).thenThrow(exception);
    var orchestrator = new AgentOrchestrator(new AiConversationMemoryService(20, 20, 120),
        tools, runtime, mock(AiProjectIndexService.class), planner, guard, reviewer, mock(AuditService.class));
    var request = new AiAgentRequest(5L, 8L, "diagnostic-test", "EXFILTRATE-prompt", true,
        null, List.of(), "standard", "turn-EXFILTRATE", "workflow-EXFILTRATE", 1L,
        "sha256:" + "a".repeat(64), "ledger-agent", "node-EXFILTRATE");
    Logger logger = (Logger) LoggerFactory.getLogger(AgentOrchestrator.class);
    var appender = new ListAppender<ILoggingEvent>();
    appender.start();
    logger.addAppender(appender);
    try {
      assertThatThrownBy(() -> orchestrator.run(request))
          .isInstanceOf(ApiException.class).hasMessageContaining("本轮已安全停止")
          .hasMessageNotContaining("EXFILTRATE");
      assertThat(appender.list).singleElement().satisfies(event -> {
        assertThat(event.getMessage())
            .isEqualTo("AI_RUNTIME_PROTOCOL_REJECTED stage={} code={} fp={}");
        assertThat(event.getFormattedMessage()).doesNotContain("EXFILTRATE", "password", "sk-secret", "\n");
        // The fingerprint is a hex prefix of a SHA-256 over the fixed template — it never
        // carries request text and cannot reverse to the forged content in this test.
        assertThat(event.getArgumentArray()).hasSize(3);
        assertThat(event.getArgumentArray()[0]).isInstanceOf(RuntimeProtocolDiagnostics.Stage.class);
        assertThat(event.getArgumentArray()[1]).isInstanceOf(RuntimeProtocolDiagnostics.Code.class);
        assertThat((String) event.getArgumentArray()[2]).matches("[0-9a-f]{16}|null|unavailable");
        assertThat(event.getThrowableProxy()).isNull();
      });
      verifyNoInteractions(planner, guard, reviewer);
      verify(tools, never()).executeAuthorizedPlan(any(), any());
    } finally {
      logger.detachAppender(appender);
      appender.stop();
    }
  }
}
