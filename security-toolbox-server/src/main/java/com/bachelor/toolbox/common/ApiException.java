package com.bachelor.toolbox.common;

public class ApiException extends RuntimeException {
  public ApiException(String message) {
    super(message);
  }

  /**
   * 保留原始异常作为 cause。
   *
   * <p>仅用单参构造会在包装时丢掉真实原因，导致鉴权失败、读超时、返回空内容等
   * 完全不同的故障在日志与审计里变得无法区分，也让排查只能看到一句笼统提示。
   */
  public ApiException(String message, Throwable cause) {
    super(message, cause);
  }
}
