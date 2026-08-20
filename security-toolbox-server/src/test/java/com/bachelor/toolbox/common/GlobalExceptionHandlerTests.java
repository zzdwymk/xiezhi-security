package com.bachelor.toolbox.common;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;
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
}
