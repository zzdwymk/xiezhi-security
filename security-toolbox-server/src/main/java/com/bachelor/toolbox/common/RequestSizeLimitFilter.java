package com.bachelor.toolbox.common;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * 全局请求体大小上限（Round 25，纵深防御）。
 *
 * <p>Spring MVC 的 {@code @RequestBody}（JSON）默认<strong>没有</strong>请求体大小上限：一个巨大的 POST 体会在
 * Jackson 反序列化过程中被整份读入内存，足以撑爆堆（OOM），且发生在认证/业务校验之前。Tomcat 的
 * {@code max-swallow-size}/{@code max-http-form-post-size} 只约束表单与"吞掉"行为，对 JSON 请求体无效。
 *
 * <p>本过滤器在所有业务过滤器之前（{@link Ordered#HIGHEST_PRECEDENCE}）检查 {@code Content-Length}：
 * 一旦声明长度超过上限即返回 413，绝不让超大请求体进入反序列化。上限取较宽松的默认值（32MB），
 * 以容纳批量字典导入等合法大请求，同时封顶病理级超大 body。
 *
 * <p>已知长度先检查声明值；未知长度（包括分块请求）在 MVC 读取前有界读取，合法请求继续提供正文。
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class RequestSizeLimitFilter extends OncePerRequestFilter {

  private final long maxBodyBytes;

  public RequestSizeLimitFilter(
      @Value("${toolbox.http.max-body-bytes:33554432}") long maxBodyBytes) {
    // 下限 1MB，防止误配成过小值；上限 512MB，避免放行病理级大 body。
    this.maxBodyBytes = Math.max(1024L * 1024, Math.min(maxBodyBytes, 512L * 1024 * 1024));
  }

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {
    long declared = request.getContentLengthLong();
    // 仅对可能携带大请求体的写方法做限制（GET 等无体，跳过）。
    boolean hasBody = !HttpMethod.GET.matches(request.getMethod())
        && !HttpMethod.HEAD.matches(request.getMethod())
        && !HttpMethod.OPTIONS.matches(request.getMethod());
    byte[] buffered = null;
    if (hasBody && declared < 0) {
      String contentType = request.getContentType();
      String normalized = contentType == null ? "" : contentType.toLowerCase(java.util.Locale.ROOT);
      if (normalized.startsWith("multipart/")
          || normalized.startsWith("application/x-www-form-urlencoded")) {
        // Servlet form/part parsing reads the original stream; do not consume it and then
        // silently delegate a broken parser. These uploads must declare their size.
        response.setStatus(411);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");
        response.getWriter().write("{\"status\":411,\"message\":\"表单或文件上传必须声明请求体长度\"}");
        return;
      }
      // Stop at limit + 1; do not let chunked JSON bypass the pre-deserialization budget.
      buffered = request.getInputStream().readNBytes((int) maxBodyBytes + 1);
      declared = buffered.length;
    }
    if (hasBody && declared > maxBodyBytes) {
      response.setStatus(413);
      response.setContentType(MediaType.APPLICATION_JSON_VALUE);
      response.setCharacterEncoding("UTF-8");
      response
          .getWriter()
          .write(
              "{\"status\":413,\"message\":\"请求体过大（上限 "
                  + (maxBodyBytes / (1024 * 1024))
                  + " MB），已拒绝\"}");
      return;
    }
    filterChain.doFilter(buffered == null ? request : new BufferedRequest(request, buffered), response);
  }

  /** Blocking MVC body replay after bounded inspection; keeps the original request metadata. */
  private static final class BufferedRequest extends jakarta.servlet.http.HttpServletRequestWrapper {
    private final jakarta.servlet.ServletInputStream input;

    BufferedRequest(HttpServletRequest request, byte[] body) {
      super(request);
      var bytes = new java.io.ByteArrayInputStream(body);
      input = new jakarta.servlet.ServletInputStream() {
        @Override public int read() { return bytes.read(); }
        @Override public int read(byte[] b, int off, int len) { return bytes.read(b, off, len); }
        @Override public boolean isFinished() { return bytes.available() == 0; }
        @Override public boolean isReady() { return true; }
        @Override public void setReadListener(jakarta.servlet.ReadListener listener) {
          throw new IllegalStateException("Buffered MVC request bodies use blocking reads");
        }
      };
    }

    @Override public jakarta.servlet.ServletInputStream getInputStream() { return input; }

    @Override public java.io.BufferedReader getReader() {
      String encoding = getCharacterEncoding();
      java.nio.charset.Charset charset = encoding == null
          ? java.nio.charset.StandardCharsets.ISO_8859_1 : java.nio.charset.Charset.forName(encoding);
      return new java.io.BufferedReader(new java.io.InputStreamReader(input, charset));
    }
  }
}
