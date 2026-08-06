package com.bachelor.toolbox.audit;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

class AuditRequestContextFilterTests {
  @Test
  void createsServerControlledRequestIdAndClearsThreadContext() throws Exception {
    var filter = new AuditRequestContextFilter();
    var request = new MockHttpServletRequest();
    request.setRemoteAddr("192.0.2.10");
    request.addHeader(AuditRequestContextFilter.REQUEST_ID_HEADER, "caller-controlled");
    var response = new MockHttpServletResponse();

    filter.doFilter(
        request,
        response,
        (req, res) -> {
          var metadata = AuditRequestContext.get();
          assertNotNull(metadata);
          assertEquals("192.0.2.10", metadata.sourceIp());
          assertNotEquals("caller-controlled", metadata.requestId());
        });

    assertDoesNotThrow(
        () ->
            java.util.UUID.fromString(
                response.getHeader(AuditRequestContextFilter.REQUEST_ID_HEADER)));
    assertNull(AuditRequestContext.get());
  }
}
