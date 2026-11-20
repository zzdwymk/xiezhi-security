package com.bachelor.toolbox.common;
import static org.assertj.core.api.Assertions.assertThat;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
class UnexpectedErrorBoundaryTests {
 @Test void unexpectedPrivateDetailsDoNotReachPublicJson(){
  var result=new GlobalExceptionHandler().handleUnexpected(new Exception("QA_PRIVATE_TOKEN C:/private/path"),new MockHttpServletRequest(),new MockHttpServletResponse());
  assertThat(result.getStatusCode().value()).isEqualTo(500);
  assertThat(result.getBody().message()).isEqualTo("服务器处理失败，请稍后重试");
 }
 @Test void committedStreamNeverGetsReplacementJsonOrStatus() throws Exception {
  var request=new MockHttpServletRequest();var response=new MockHttpServletResponse();
  response.setContentType("text/event-stream");response.setStatus(200);response.flushBuffer();
  assertThat(new GlobalExceptionHandler().handleUnexpected(new Exception("QA detail"),request,response)).isNull();
  assertThat(response.getStatus()).isEqualTo(200);assertThat(response.getContentAsString()).isEmpty();
 }
}
