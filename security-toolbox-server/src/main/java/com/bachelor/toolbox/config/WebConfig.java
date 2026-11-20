package com.bachelor.toolbox.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.AsyncSupportConfigurer;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebConfig implements WebMvcConfigurer {
  /**
   * 只允许桌面 file 来源与本机开发服务器，而不是任意 Origin。
   *
   * <p>原配置使用 allowedOriginPatterns("*")，任何网页都能读取本地 API 响应；这是
   * 本地服务上典型的 CORS 过宽配置。
   */
  @Value(
      "${toolbox.cors.allowed-origin-patterns:"
          + "http://localhost:*,http://127.0.0.1:*,file://,null}")
  private String allowedOriginPatterns;

  @Override
  public void configureAsyncSupport(AsyncSupportConfigurer configurer) {
    // Streaming AI requests have no fixed wall-clock deadline. Upstream socket reads still use
    // the configured 180-second inactivity timeout, which resets whenever an SSE event arrives.
    configurer.setDefaultTimeout(-1);
  }

  @Override
  public void addCorsMappings(CorsRegistry registry) {
    String[] patterns =
        java.util.Arrays.stream(allowedOriginPatterns.split(","))
            .map(String::trim)
            .filter(value -> !value.isEmpty())
            .toArray(String[]::new);
    registry
        .addMapping("/api/**")
        .allowedOriginPatterns(patterns)
        .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")
        .allowedHeaders("*");
  }
}
