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
        Arguments.of("AI Runtime 本轮未完成：EVIDENCE_ASSESSMENT_FAILED", "RUNTIME_TERMINAL", "EVIDENCE_ASSESSMENT_FAILED"),
        Arguments.of("AI Runtime 返回失败终态：TURN_TIMEOUT", "RUNTIME_TERMINAL", "TURN_TIMEOUT"),
        Arguments.of("AI Runtime 本轮未完成：MODEL_ACCESS_DENIED", "RUNTIME_TERMINAL", "MODEL_ACCESS_DENIED"),
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
  void nullMessageIsUnknown() {
    assertThat(RuntimeProtocolDiagnostics.classify(
        new AiAgentRuntimeClient.RuntimeProtocolException(null)).code())
        .isEqualTo(RuntimeProtocolDiagnostics.Code.UNKNOWN_PROTOCOL_FAILURE);
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
        .contains("Harness 协议校验", "尚未提交审批申请", "未创建检测任务")
        .doesNotContain("未能完成证据评估", "模型服务连接超时");
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
        assertThat(event.getMessage()).isEqualTo("AI_RUNTIME_PROTOCOL_REJECTED stage={} code={}");
        assertThat(event.getFormattedMessage()).doesNotContain("EXFILTRATE", "password", "sk-secret", "\n");
        assertThat(event.getArgumentArray()).hasSize(2);
        assertThat(event.getArgumentArray()[0]).isInstanceOf(RuntimeProtocolDiagnostics.Stage.class);
        assertThat(event.getArgumentArray()[1]).isInstanceOf(RuntimeProtocolDiagnostics.Code.class);
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
