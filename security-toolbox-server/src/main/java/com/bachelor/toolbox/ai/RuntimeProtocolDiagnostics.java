package com.bachelor.toolbox.ai;

import java.util.Set;

/** Bounded server diagnostics. Never log the input message, its fields, or its cause. */
final class RuntimeProtocolDiagnostics {
  enum Stage { RUNTIME_TERMINAL, JAVA_LEDGER, JAVA_SEMANTIC, JAVA_FIELDS, JAVA_STREAM, JAVA_PROTOCOL }

  enum Code {
    ROUTE_FAILED, GROUNDED_GENERATION_FAILED, EVIDENCE_ASSESSMENT_FAILED, RETRIEVAL_FAILED,
    RETRIEVAL_GUARD_DENIED, TURN_TIMEOUT, MODEL_ACCESS_DENIED, MODEL_RATE_LIMITED,
    MODEL_TIMEOUT, MODEL_SERVICE_UNAVAILABLE, MODEL_REQUEST_FAILED, UNKNOWN_RUNTIME_TERMINAL,
    LEDGER_DIGEST_INVALID, LEDGER_PERSISTENCE_INVALID, EVENT_IDENTITY_INVALID,
    ROUTE_PLAN_MISMATCH, AUTO_DECISION_INVALID, PLAN_EVENT_MISMATCH,
    EVIDENCE_SCOPE_INVALID, AUTHORIZATION_MISMATCH, TERMINAL_STATE_MISMATCH,
    FIELD_CONTRACT_INVALID, EVENT_JSON_INVALID, STREAM_INCOMPLETE, UNKNOWN_PROTOCOL_FAILURE
  }

  record Failure(Stage stage, Code code) {}

  private static final Set<Code> TERMINAL_CODES = Set.of(
      Code.ROUTE_FAILED, Code.GROUNDED_GENERATION_FAILED, Code.EVIDENCE_ASSESSMENT_FAILED,
      Code.RETRIEVAL_FAILED, Code.RETRIEVAL_GUARD_DENIED, Code.TURN_TIMEOUT,
      Code.MODEL_ACCESS_DENIED, Code.MODEL_RATE_LIMITED, Code.MODEL_TIMEOUT,
      Code.MODEL_SERVICE_UNAVAILABLE, Code.MODEL_REQUEST_FAILED);

  private RuntimeProtocolDiagnostics() {}

  static String userMessage(Failure failure) {
    String stopped = "本轮已安全停止，尚未提交审批申请，未创建检测任务，未执行任何检测。";
    if (failure.stage() != Stage.RUNTIME_TERMINAL) {
      return "AI Runtime 返回内容未通过 Harness 协议校验：智能服务返回内容格式不完整，"
          + stopped + "请检查模型连接后重试";
    }
    return switch (failure.code()) {
      case EVIDENCE_ASSESSMENT_FAILED ->
          "AI Runtime 未能完成证据评估，" + stopped + "请检查模型连接后重试";
      case GROUNDED_GENERATION_FAILED ->
          "AI Runtime 未能根据项目证据生成回答，" + stopped + "请检查模型连接后重试";
      case ROUTE_FAILED ->
          "AI Runtime 未能完成请求意图判断，" + stopped + "请检查模型连接后重试";
      case RETRIEVAL_FAILED ->
          "AI Runtime 项目证据检索失败，" + stopped + "请检查项目索引和检索服务后重试";
      case RETRIEVAL_GUARD_DENIED ->
          "AI Runtime 项目证据检索未通过授权检查，" + stopped + "请检查项目和目标授权范围";
      case TURN_TIMEOUT ->
          "模型在规定时间内没有完成回答，" + stopped + "请检查模型连接后重试";
      case MODEL_ACCESS_DENIED ->
          "模型服务拒绝了这次请求，" + stopped + "请检查代理权限、模型权限，或改用兼容的模型服务后重试";
      case MODEL_RATE_LIMITED ->
          "模型服务当前请求过多，" + stopped + "请稍后重试";
      case MODEL_TIMEOUT ->
          "模型服务连接超时，" + stopped + "请检查服务状态后重试";
      case MODEL_SERVICE_UNAVAILABLE ->
          "模型服务暂时不可用，" + stopped + "请检查服务状态后重试";
      case MODEL_REQUEST_FAILED ->
          "模型服务请求失败，" + stopped + "请检查模型地址和连接后重试";
      default -> "AI Runtime 未能完成本轮请求，" + stopped + "请检查服务状态后重试";
    };
  }

  static Failure classify(AiAgentRuntimeClient.RuntimeProtocolException failure) {
    String message = failure.getMessage();
    if (message == null) return new Failure(Stage.JAVA_PROTOCOL, Code.UNKNOWN_PROTOCOL_FAILURE);
    for (Code code : TERMINAL_CODES) {
      if (message.equals("AI Runtime 本轮未完成：" + code.name())
          || message.equals("AI Runtime 返回失败终态：" + code.name())) {
        return new Failure(Stage.RUNTIME_TERMINAL, code);
      }
    }
    if (message.startsWith("AI Runtime 本轮未完成：")
        || message.startsWith("AI Runtime 返回失败终态：")
        || message.equals("AI Runtime Harness 拒绝了本轮计划")) {
      return new Failure(Stage.RUNTIME_TERMINAL, Code.UNKNOWN_RUNTIME_TERMINAL);
    }
    return switch (message) {
      case "AI Runtime 候选 Ledger 摘要链无效" ->
          new Failure(Stage.JAVA_LEDGER, Code.LEDGER_DIGEST_INVALID);
      case "Java Ledger 未完整持久化 Runtime 事件流", "Java Ledger 持久化回执与 Runtime 事件不一致" ->
          new Failure(Stage.JAVA_LEDGER, Code.LEDGER_PERSISTENCE_INVALID);
      case "AI Runtime 运行标识或状态版本不连续", "AI Runtime 重复使用 eventId" ->
          new Failure(Stage.JAVA_LEDGER, Code.EVENT_IDENTITY_INVALID);
      case "AI Runtime route intent 与最终计划语义不一致",
          "AI Runtime route intent 与 reason 不一致", "AI Runtime route 检索决策与 intent 不一致",
          "AI Runtime plan intent 与 actions 不一致" ->
          new Failure(Stage.JAVA_SEMANTIC, Code.ROUTE_PLAN_MISMATCH);
      case "AI Runtime AUTO executionDecision 与路由不一致",
          "AI Runtime AUTO route 缺少 executionDecision", "AUTO 不允许使用旧规划路径推断执行许可" ->
          new Failure(Stage.JAVA_SEMANTIC, Code.AUTO_DECISION_INVALID);
      case "AI Runtime plan 事件与终态计划不一致", "AI Runtime plan 事件与终态 provenance 不一致",
          "AI Runtime finish answer 与最终计划 answer 不一致",
          "AI Runtime finish provenance 与最终计划不一致",
          "AI Runtime plan actionCount 与 actions 不一致", "AI Runtime plan actionable 状态不一致",
          "AI Runtime plan steps 与 actions 数量不一致",
          "AI Runtime plan step parameters 与 action 不一致" ->
          new Failure(Stage.JAVA_SEMANTIC, Code.PLAN_EVENT_MISMATCH);
      case "AI Runtime 计划引用了当前 EvidenceBundle 之外的证据",
          "AI Runtime action 引用了未声明证据", "项目证据行动必须声明 evidenceRefs",
          "AI Runtime Evidence 超出当前项目或目标 scope", "AI Runtime Evidence 会话 scope 无效",
          "AI Runtime Evidence item 超出当前目标 scope", "GENERAL 计划不得引用项目证据",
          "PROJECT_EVIDENCE 计划缺少证据引用", "INSUFFICIENT_EVIDENCE 只能返回无行动澄清" ->
          new Failure(Stage.JAVA_SEMANTIC, Code.EVIDENCE_SCOPE_INVALID);
      case "AI Runtime 未授权执行本轮计划", "AI Runtime 未获授权却发送 tool 事件",
          "AI Runtime authorization_guard status 与计划不一致",
          "AI Runtime authorization_guard 决策明细不一致",
          "AI Runtime NOT_APPLICABLE 授权守卫与计划不一致",
          "AI Runtime approval_required 与授权决策不一致", "AI Runtime approval action 越出请求范围" ->
          new Failure(Stage.JAVA_SEMANTIC, Code.AUTHORIZATION_MISMATCH);
      case "AI Runtime Evidence 失败状态未传播到终态",
          "AI Runtime Harness 中间状态未正确传播到终态",
          "失败的 route 必须传播 FAILED 终态", "AI Runtime route failureCode 与终态原因不一致" ->
          new Failure(Stage.JAVA_SEMANTIC, Code.TERMINAL_STATE_MISMATCH);
      case "AI Runtime 事件不是合法 JSON", "AI Runtime 事件必须是 JSON 对象" ->
          new Failure(Stage.JAVA_FIELDS, Code.EVENT_JSON_INVALID);
      case "AI Runtime 流在终态前中断", "AI Runtime 重复发送 finish 终态",
          "AI Runtime 在终态后继续发送事件", "AI Runtime 混合了不完整的 SSE 与 NDJSON 事件" ->
          new Failure(Stage.JAVA_STREAM, Code.STREAM_INCOMPLETE);
      default -> classifyFieldContract(message);
    };
  }

  private static Failure classifyFieldContract(String message) {
    // These are the fixed validation message templates. Labels are deliberately discarded:
    // even a forged field name or unknown terminal reason can never reach the logger.
    if (message.startsWith("AI Runtime ")
        && (message.endsWith(" 格式无效") || message.endsWith(" 标识格式无效")
            || message.endsWith(" 必须是正整数") || message.endsWith(" 超出范围")
            || message.endsWith(" 必须是对象") || message.endsWith(" 包含未知字段")
            || message.contains(" 缺少字段 ") || message.endsWith(" 无效")
            || message.equals("AI Runtime 返回未知事件类型")
            || message.equals("AI Runtime 返回了未知流字段"))) {
      return new Failure(Stage.JAVA_FIELDS, Code.FIELD_CONTRACT_INVALID);
    }
    return new Failure(Stage.JAVA_PROTOCOL, Code.UNKNOWN_PROTOCOL_FAILURE);
  }
}
