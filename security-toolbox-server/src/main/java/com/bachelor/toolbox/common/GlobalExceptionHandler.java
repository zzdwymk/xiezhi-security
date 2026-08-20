package com.bachelor.toolbox.common;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.resource.NoResourceFoundException;

@RestControllerAdvice
public class GlobalExceptionHandler {
  private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

  @ExceptionHandler(ApiException.class)
  public ResponseEntity<ApiErrorResponse> handleApi(ApiException ex) {
    return error(HttpStatus.BAD_REQUEST, localizedMessage(ex.getMessage(), "请求处理失败"));
  }

  @ExceptionHandler(BadCredentialsException.class)
  public ResponseEntity<ApiErrorResponse> handleBadCredentials() {
    return error(HttpStatus.UNAUTHORIZED, "用户名或密码错误");
  }

  @ExceptionHandler(MethodArgumentNotValidException.class)
  public ResponseEntity<ApiErrorResponse> handleValidation(MethodArgumentNotValidException ex) {
    FieldError first = ex.getBindingResult().getFieldErrors().stream().findFirst().orElse(null);
    String message =
        first == null || first.getDefaultMessage() == null || first.getDefaultMessage().isBlank()
            ? "请求参数不合法"
            : first.getDefaultMessage();
    return error(HttpStatus.BAD_REQUEST, localizedMessage(message, "请求参数不合法"));
  }

  @ExceptionHandler(IllegalArgumentException.class)
  public ResponseEntity<ApiErrorResponse> handleIllegalArgument(IllegalArgumentException ex) {
    return error(HttpStatus.BAD_REQUEST, localizedMessage(ex.getMessage(), "请求参数不合法"));
  }

  @ExceptionHandler(MethodArgumentTypeMismatchException.class)
  public ResponseEntity<ApiErrorResponse> handleTypeMismatch() {
    return error(HttpStatus.BAD_REQUEST, "请求参数格式不正确");
  }

  @ExceptionHandler(MissingServletRequestParameterException.class)
  public ResponseEntity<ApiErrorResponse> handleMissingParameter(
      MissingServletRequestParameterException ex) {
    return error(HttpStatus.BAD_REQUEST, "缺少必要请求参数：" + ex.getParameterName());
  }

  @ExceptionHandler(HttpMessageNotReadableException.class)
  public ResponseEntity<ApiErrorResponse> handleUnreadableMessage() {
    return error(HttpStatus.BAD_REQUEST, "请求内容格式不正确");
  }

  @ExceptionHandler(ResponseStatusException.class)
  public ResponseEntity<ApiErrorResponse> handleResponseStatus(ResponseStatusException ex) {
    return error(ex.getStatusCode(), localizedMessage(ex.getReason(), "请求处理失败"));
  }

  @ExceptionHandler(NoResourceFoundException.class)
  public ResponseEntity<ApiErrorResponse> handleNoResource(NoResourceFoundException ex) {
    return error(HttpStatus.NOT_FOUND, "请求资源不存在");
  }

  @ExceptionHandler(Exception.class)
  public ResponseEntity<ApiErrorResponse> handleUnexpected(Exception ex) {
    log.error("服务器处理请求时发生未预期异常", ex);
    return error(HttpStatus.INTERNAL_SERVER_ERROR, "服务器处理失败，请稍后重试");
  }

  private ResponseEntity<ApiErrorResponse> error(HttpStatusCode status, String message) {
    return ResponseEntity.status(status).body(ApiErrorResponse.of(status.value(), message));
  }

  private String localizedMessage(String message, String fallback) {
    if (message == null || message.isBlank()) {
      return fallback;
    }
    boolean containsChinese =
        message
            .codePoints()
            .anyMatch(
                codePoint -> Character.UnicodeScript.of(codePoint) == Character.UnicodeScript.HAN);
    return containsChinese ? message : fallback;
  }
}
