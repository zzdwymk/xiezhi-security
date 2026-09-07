package com.bachelor.toolbox.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.AsyncSupportConfigurer;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebConfig implements WebMvcConfigurer {
  @Override
  public void configureAsyncSupport(AsyncSupportConfigurer configurer) {
    // Streaming AI requests have no fixed wall-clock deadline. Upstream socket reads still use
    // the configured 180-second inactivity timeout, which resets whenever an SSE event arrives.
    configurer.setDefaultTimeout(-1);
  }

  @Override
  public void addCorsMappings(CorsRegistry registry) {
    registry
        .addMapping("/api/**")
        .allowedOriginPatterns("*")
        .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")
        .allowedHeaders("*");
  }
}
