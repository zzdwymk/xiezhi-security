package com.bachelor.toolbox.common;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

/**
 * 全局请求体大小上限过滤器——Round 25。
 *
 * <p>JSON {@code @RequestBody} 默认无请求体大小上限，超大 POST 会在反序列化前撑爆内存。
 * 本过滤器在业务之前按 Content-Length 拒绝超大请求体（413）。
 */
@DisplayName("请求体大小上限过滤器（Round 25）")
class RequestSizeLimitFilterTest {

  private static final long MAX = 1_000_000; // 1MB，便于测试

  private final RequestSizeLimitFilter filter = new RequestSizeLimitFilter(MAX);

  @Test
  @DisplayName("RSL-1 声明 Content-Length 超上限的 POST → 413 且不进入业务链")
  void oversizedPostRejected() throws Exception {
    MockHttpServletRequest req = new MockHttpServletRequest("POST", "/api/tasks");
    req.setContent(new byte[1024*1024 + 10]); // > 1MB 下限
    MockHttpServletResponse resp = new MockHttpServletResponse();
    FilterChain chain = mock(FilterChain.class);

    filter.doFilter(req, resp, chain);

    assertThat(resp.getStatus()).isEqualTo(413);
    verify(chain, never()).doFilter(req, resp);
  }

  @Test
  @DisplayName("RSL-2 正常大小的 POST → 放行到业务链")
  void normalPostPasses() throws Exception {
    MockHttpServletRequest req = new MockHttpServletRequest("POST", "/api/tasks");
    req.setContent(new byte[100]);
    MockHttpServletResponse resp = new MockHttpServletResponse();
    FilterChain chain = mock(FilterChain.class);

    filter.doFilter(req, resp, chain);

    assertThat(resp.getStatus()).isEqualTo(200);
    verify(chain).doFilter(req, resp);
  }

  @Test
  @DisplayName("RSL-3 GET 即便带大 Content-Length 也跳过限制（无体）")
  void getSkipsLimit() throws Exception {
    MockHttpServletRequest req = new MockHttpServletRequest("GET", "/api/projects");
    req.addHeader("Content-Length", String.valueOf(MAX * 10));
    MockHttpServletResponse resp = new MockHttpServletResponse();
    FilterChain chain = mock(FilterChain.class);

    filter.doFilter(req, resp, chain);
    verify(chain).doFilter(req, resp);
  }
}
