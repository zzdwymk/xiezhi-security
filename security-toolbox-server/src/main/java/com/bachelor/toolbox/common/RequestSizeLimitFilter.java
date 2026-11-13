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
 * <p>仅依据 {@code Content-Length} 判断；分块传输（无 CL）在本平台非标准用法，如需也可在网关层限制。
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
    filterChain.doFilter(request, response);
  }
}
