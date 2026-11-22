package com.bachelor.toolbox.common;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.ConnectException;
import java.net.SocketTimeoutException;
import java.net.http.HttpTimeoutException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.context.request.async.AsyncRequestTimeoutException;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.resource.NoResourceFoundException;
import org.springframework.web.servlet.HandlerMapping;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

@RestControllerAdvice
public class GlobalExceptionHandler {
  private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

  @ExceptionHandler(ApiException.class)
  public ResponseEntity<ApiErrorResponse> handleApi(
      ApiException ex, HttpServletRequest request, HttpServletResponse response) {
    log.warn("API 请求处理异常: {}", localizedMessage(ex.getMessage(), ""), ex);
    if (isEventStream(request, response)) {
      log.debug("流式请求在事件流阶段失败，已终止事件流而不追写 JSON 错误体");
      return null;
    }
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

  /**
   * Round 298：客户端只接受无法提供的媒体类型（如 {@code Accept: application/xml}）时必须回 406。
   * 兜底成 500 且响应体为空，客户端既拿不到状态语义也拿不到说明。
   */
  @ExceptionHandler(org.springframework.web.HttpMediaTypeNotAcceptableException.class)
  public ResponseEntity<ApiErrorResponse> handleMediaTypeNotAcceptable(
      org.springframework.web.HttpMediaTypeNotAcceptableException ex) {
    log.warn("无法提供客户端可接受的响应类型: {}", ex.getMessage());
    return error(HttpStatus.NOT_ACCEPTABLE, "无法提供客户端可接受的响应类型");
  }

  /**
   * Round 296：请求体类型不支持同样是客户端错误，必须回 415。
   * 与 R295 的 405 同类：兜底成 500 会把客户端用法错误记成服务端故障。
   */
  @ExceptionHandler(org.springframework.web.HttpMediaTypeNotSupportedException.class)
  public ResponseEntity<ApiErrorResponse> handleMediaTypeNotSupported(
      org.springframework.web.HttpMediaTypeNotSupportedException ex) {
    log.warn("请求体类型不支持: {}", ex.getMessage());
    return error(HttpStatus.UNSUPPORTED_MEDIA_TYPE, "请求体类型不支持");
  }

  /**
   * Round 295：客户端用错 HTTP 方法（例如对只有 PUT/DELETE 的路径发 GET）是**客户端错误**，
   * 必须回 405 而不是被兜底成 500——否则监控上会把用法错误记成服务端故障。
   */
  @ExceptionHandler(org.springframework.web.HttpRequestMethodNotSupportedException.class)
  public ResponseEntity<ApiErrorResponse> handleMethodNotSupported(
      org.springframework.web.HttpRequestMethodNotSupportedException ex) {
    log.warn("请求方法不支持: {}", ex.getMessage());
    return error(HttpStatus.METHOD_NOT_ALLOWED, "请求方法不支持");
  }

  /**
   * Round 288：并发更新冲突（乐观锁 / 悲观锁读到的版本已过期）是**预期内**的业务结果，
   * 不能落到通用的 {@link DataAccessException} 分支被报成 500。
   */
  @ExceptionHandler(org.springframework.dao.OptimisticLockingFailureException.class)
  public ResponseEntity<ApiErrorResponse> handleOptimisticLock(
      org.springframework.dao.OptimisticLockingFailureException ex) {
    log.warn("并发更新冲突: {}", ex.getMessage());
    return error(HttpStatus.CONFLICT, "数据已被其他操作修改，请刷新后重试");
  }

  @ExceptionHandler(DataAccessException.class)
  public ResponseEntity<ApiErrorResponse> handleDataAccess(DataAccessException ex) {
    log.error("数据库或本地存储访问异常", ex);
    return error(
        HttpStatus.INTERNAL_SERVER_ERROR, "数据库或本地存储访问失败，请检查服务状态后重试");
  }

  @ExceptionHandler(value = {HttpTimeoutException.class, SocketTimeoutException.class})
  public ResponseEntity<ApiErrorResponse> handleHttpTimeout(Exception ex) {
    log.warn("外部请求连接超时: {}", ex.getMessage());
    return error(HttpStatus.INTERNAL_SERVER_ERROR, "外部连接超时，请稍后重试或检查网络");
  }

  @ExceptionHandler(AsyncRequestTimeoutException.class)
  public ResponseEntity<ApiErrorResponse> handleAsyncTimeout(
      HttpServletRequest request, HttpServletResponse response) {
    // A started event stream has already sent its status and media type. Never
    // append an API JSON error to it or try to change a committed response.
    if (response.isCommitted()) return null;
    if (isEventStream(request, response)) {
      response.setStatus(HttpStatus.SERVICE_UNAVAILABLE.value());
      return null;
    }
    return error(HttpStatus.SERVICE_UNAVAILABLE, "请求处理超时，请稍后重试");
  }

  /**
   * True when the failing request is an SSE stream. Writing an {@link ApiErrorResponse} to a stream
   * raises {@link org.springframework.http.converter.HttpMessageNotWritableException} because the
   * response carries {@code text/event-stream}, which hides the real failure and emits a cascade of
   * secondary errors. Such requests must only be terminated, never answered with JSON.
   */
  private boolean isEventStream(HttpServletRequest request, HttpServletResponse response) {
    if (request == null || response == null) return false;
    if (response.isCommitted()) return true;
    boolean eventStream = false;
    String contentType = response.getContentType();
    if (contentType != null) {
      try {
        eventStream = MediaType.TEXT_EVENT_STREAM.includes(MediaType.parseMediaType(contentType));
      } catch (RuntimeException ignored) {
        eventStream = false;
      }
    }
    // DispatcherServlet clears the producible-media-types attribute before exception
    // resolution, so a stream that has not sent its first event must be identified
    // from the original handler rather than that attribute.
    Object originalHandler = request.getAttribute(HandlerMapping.BEST_MATCHING_HANDLER_ATTRIBUTE);
    if (originalHandler instanceof HandlerMethod handler) {
      Class<?> returnType = handler.getReturnType().getParameterType();
      eventStream |= SseEmitter.class.isAssignableFrom(returnType);
    }
    return eventStream;
  }

  @ExceptionHandler(ConnectException.class)
  public ResponseEntity<ApiErrorResponse> handleConnect(ConnectException ex) {
    log.warn("外部连接失败: {}", ex.getMessage());
    return error(HttpStatus.INTERNAL_SERVER_ERROR, "无法连接外部服务，请检查服务状态后重试");
  }

  @ExceptionHandler(UncheckedIOException.class)
  public ResponseEntity<ApiErrorResponse> handleUncheckedIo(
      UncheckedIOException ex, HttpServletRequest request, HttpServletResponse response) {
    if (isEventStream(request, response)) {
      log.debug("流式响应写入中断，已终止事件流而不追写 JSON 错误体");
      return null;
    }
    log.error("本地文件读写失败", ex);
    return error(HttpStatus.INTERNAL_SERVER_ERROR, "本地文件读写失败，请检查磁盘空间和访问权限后重试");
  }

  @ExceptionHandler(IOException.class)
  public ResponseEntity<ApiErrorResponse> handleIo(
      IOException ex, HttpServletRequest request, HttpServletResponse response) {
    if (isEventStream(request, response)) {
      log.debug("流式响应写入中断，已终止事件流而不追写 JSON 错误体");
      return null;
    }
    log.error("本地文件或流处理失败", ex);
    return error(HttpStatus.INTERNAL_SERVER_ERROR, "本地文件或流处理失败，请检查磁盘空间和访问权限后重试");
  }

  @ExceptionHandler(InterruptedException.class)
  public ResponseEntity<ApiErrorResponse> handleInterrupted(InterruptedException ex) {
    Thread.currentThread().interrupt();
    log.warn("操作被中断: {}", ex.getMessage());
    return error(HttpStatus.INTERNAL_SERVER_ERROR, "操作被中断，请稍后重试");
  }

  @ExceptionHandler(Exception.class)
  public ResponseEntity<ApiErrorResponse> handleUnexpected(
      Exception ex, HttpServletRequest request, HttpServletResponse response) {
    if (isEventStream(request, response)) {
      // 事件流已建立或已判定为 SSE：保留原始异常，绝不追写 JSON。
      log.error("流式请求在事件流阶段发生未预期异常，已终止事件流", ex);
      return null;
    }
    log.error("服务器处理请求时发生未预期异常", ex);
    return error(HttpStatus.INTERNAL_SERVER_ERROR, "服务器处理失败，请稍后重试");
  }

  /**
   * Round 278：错误响应必须与请求可接受的媒体类型兼容。
   *
   * <p>报告类端点声明 {@code produces = text/html}；若此处无条件写 JSON 体，Spring 找不到可写转换器，
   * 异常处理器自身会抛 {@code HttpMessageNotWritableException}，把本应是 400/403 的拒绝放大成
   * 500 ServletException（错误页还可能带出内部异常链）。因此仅当调用方能接受 JSON 时写结构化错误体，
   * 否则返回同状态码的空体：状态语义正确，且不向 HTML 调用方暴露内部细节。
   */
  private ResponseEntity<ApiErrorResponse> error(HttpStatusCode status, String message) {
    if (!acceptsJson()) {
      return ResponseEntity.status(status).build();
    }
    return ResponseEntity.status(status).body(ApiErrorResponse.of(status.value(), message));
  }

  /** 缺省或无 Accept 头按 JSON 处理（保持既有 API 契约）；显式只接受 HTML/文本时降级为空体。 */
  private static boolean acceptsJson() {
    var attributes =
        org.springframework.web.context.request.RequestContextHolder.getRequestAttributes();
    if (!(attributes
        instanceof
        org.springframework.web.context.request.ServletRequestAttributes servletAttributes)) {
      return true;
    }
    String accept = servletAttributes.getRequest().getHeader(HttpHeaders.ACCEPT);
    if (accept == null || accept.isBlank()) return true;
    String normalized = accept.toLowerCase(java.util.Locale.ROOT);
    return normalized.contains("*/*")
        || normalized.contains("application/json")
        || normalized.contains("application/*");
  }

  private String localizedMessage(String message, String fallback) {
    if (message == null || message.isBlank()) {
      return fallback;
    }
    if (message.length() > 2048 || java.util.regex.Pattern.compile(
        "(?i)(?:\\b[a-z]:[\\\\/]|/(?:home|users|usr|var|opt|tmp|private)/|exception|traceback|stack trace|\\b[\\w-]*(?:password|passwd|token|api[-_ ]?key|secret|authorization)[\\w-]*[\"']?\\s*[:=])")
        .matcher(message).find()) {
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
