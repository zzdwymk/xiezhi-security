package com.bachelor.toolbox.common;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.ConnectException;
import java.net.SocketTimeoutException;
import java.net.http.HttpTimeoutException;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpMethod;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.resource.NoResourceFoundException;

class GlobalExceptionHandlerTests {
  private final GlobalExceptionHandler handler = new GlobalExceptionHandler();

  @Test
  void localizesAuthenticationErrors() {
    var response = handler.handleBadCredentials();

    assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
    assertEquals("用户名或密码错误", response.getBody().message());
  }

  @Test
  void doesNotExposeUnexpectedExceptionDetails() {
    var response = handler.handleUnexpected(new IllegalStateException("sensitive internal detail"));

    assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
    assertEquals("服务器处理失败，请稍后重试", response.getBody().message());
  }

  @Test
  void replacesEnglishBusinessErrorsWithChineseFallback() {
    var response = handler.handleApi(new ApiException("internal detail"));

    assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
    assertEquals("请求处理失败", response.getBody().message());
  }

  @Test
  void preservesLocalizedResponseStatusAndReason() {
    var response =
        handler.handleResponseStatus(new ResponseStatusException(HttpStatus.FORBIDDEN, "仅允许从本机访问"));

    assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode());
    assertEquals("仅允许从本机访问", response.getBody().message());
  }

  @Test
  void mapsMissingStaticResourcesToNotFoundWithoutLeakingAsServerError() {
    var response = handler.handleNoResource(new NoResourceFoundException(HttpMethod.GET, ""));

    assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());
    assertEquals("请求资源不存在", response.getBody().message());
  }

  @Test
  void localizesDataAccessFailureWithoutLeakingInternals() {
    var response =
        handler.handleDataAccess(new DataAccessResourceFailureException("cannot connect to db"));

    assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
    assertEquals("数据库或本地存储访问失败，请检查服务状态后重试", response.getBody().message());
  }

  @Test
  void localizesHttpTimeoutWithoutLeakingInternals() {
    var response = handler.handleHttpTimeout(new HttpTimeoutException("timed out"));

    assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
    assertEquals("外部连接超时，请稍后重试或检查网络", response.getBody().message());
  }

  @Test
  void localizesSocketTimeoutWithoutLeakingInternals() {
    var response = handler.handleHttpTimeout(new SocketTimeoutException("read timed out"));

    assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
    assertEquals("外部连接超时，请稍后重试或检查网络", response.getBody().message());
  }

  @Test
  void localizesConnectFailureWithoutLeakingInternals() {
    var response = handler.handleConnect(new ConnectException("connection refused"));

    assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
    assertEquals("无法连接外部服务，请检查服务状态后重试", response.getBody().message());
  }

  @Test
  void localizesIoFailureWithoutLeakingInternals() {
    var response = handler.handleIo(new IOException("disk full"));

    assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
    assertEquals(
        "本地文件或流处理失败，请检查磁盘空间和访问权限后重试", response.getBody().message());
  }

  @Test
  void localizesUncheckedIoFailureWithoutLeakingInternals() {
    var response = handler.handleUncheckedIo(new UncheckedIOException(new IOException("locked")));

    assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
    assertEquals("本地文件读写失败，请检查磁盘空间和访问权限后重试", response.getBody().message());
  }

  @Test
  void localizesInterruptedOperationWithoutLeakingInternals() {
    var response = handler.handleInterrupted(new InterruptedException("cancelled"));

    assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
    assertEquals("操作被中断，请稍后重试", response.getBody().message());
  }
}
