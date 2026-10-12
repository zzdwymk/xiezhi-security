package com.bachelor.toolbox.ai.guard;

import com.bachelor.toolbox.common.ApiException;

/**
 * 护栏拒绝执行时抛出的异常（设计文档 §6.0 的四类威胁 T1-T4）。
 *
 * <p>刻意继承 {@link ApiException}：护栏的拒绝必须与平台既有的错误语义一致，由 {@code GlobalExceptionHandler} 统一转成
 * 4xx 响应，而不是变成 500。同时它是 {@link RuntimeException}，因此"忘记 catch"不会意外放行。
 *
 * <p>异常携带 {@link #layer()}，用于回答论文 §9.5 的"越界拦截率"指标——必须能证明是<strong>哪一层</strong>拦下的，而不是笼统地
 * 报一个 400。
 */
public class CapabilityDeniedException extends ApiException {

  /** 护栏四层（设计文档 §6.1）。 */
  public enum Layer {
    /** L-A 授权边界：管"打谁"。 */
    AUTHORIZATION("L-A"),
    /** L-B 能力准入：管"能调什么"。 */
    ADMISSION("L-B"),
    /** L-C 参数校验：管"怎么调"。 */
    PARAMETER("L-C"),
    /** L-D 唯一入口：管"能不能绕"。 */
    ENTRYPOINT("L-D");

    private final String label;

    Layer(String label) {
      this.label = label;
    }

    /** 设计文档中的层编号（L-A/L-B/L-C/L-D）。 */
    public String label() {
      return label;
    }
  }

  private final Layer layer;
  private final String reasonCode;
  private final String capabilityCode;

  /**
   * 附加审计详情（可选）。用于把"护栏自身故障"这类信息带进审计账本。
   *
   * <p>刻意<strong>不</strong>放进 {@link #getMessage()}：拒绝消息会返回给调用方，
   * 而审计详情只在内部可见。这样既能留痕，又不泄露内部实现细节。
   */
  private final java.util.Map<String, Object> auditDetails = new java.util.LinkedHashMap<>();

  public CapabilityDeniedException(
      Layer layer, String reasonCode, String capabilityCode, String message) {
    super(message);
    this.layer = layer;
    this.reasonCode = reasonCode;
    this.capabilityCode = capabilityCode;
  }

  /** 拦下本次调用的护栏层。 */
  public Layer layer() {
    return layer;
  }

  /** 机器可读的拒绝原因码，例如 {@code BLOCKED_CAPABILITY}、{@code TARGET_BINDING_UNRESOLVED}。 */
  public String reasonCode() {
    return reasonCode;
  }

  /** 被拒绝的能力码；未知能力时为原始请求码。 */
  public String capabilityCode() {
    return capabilityCode;
  }

  /** 附加审计详情（只读视图）。 */
  public java.util.Map<String, Object> auditDetails() {
    return java.util.Collections.unmodifiableMap(auditDetails);
  }

  /** 追加一条审计详情；返回自身以便链式调用。 */
  public CapabilityDeniedException withAuditDetail(String key, Object value) {
    auditDetails.put(key, value);
    return this;
  }

  @Override
  public String toString() {
    return "CapabilityDeniedException["
        + layer.label()
        + " "
        + reasonCode
        + " capability="
        + capabilityCode
        + "]: "
        + getMessage();
  }
}
