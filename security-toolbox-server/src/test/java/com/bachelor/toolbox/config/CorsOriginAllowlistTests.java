package com.bachelor.toolbox.config;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.test.web.servlet.MockMvc;

/**
 * Round 227：本地 API 的 CORS 必须只允许桌面/本机开发来源，不能让任意网站读取响应。
 *
 * <p>原配置 `.allowedOriginPatterns("*")` 会对 `Origin: https://evil.example` 回显
 * `Access-Control-Allow-Origin: https://evil.example`，使任意网页可跨域读取本地 API 响应。
 */
@SpringBootTest(
    properties = {
      "spring.datasource.url=jdbc:h2:mem:cors-origin-test;MODE=PostgreSQL;DB_CLOSE_DELAY=-1",
      "spring.jpa.hibernate.ddl-auto=create-drop",
      "toolbox.ai.api-key=",
      "toolbox.ai.enabled=false",
      "toolbox.auth.admin-password=test-admin-password-7bbbe095d8724fcb",
      "toolbox.auth.jwt-secret=test-jwt-secret-cdc24d415ad843aa9ef313028ae9be30",
      "toolbox.traffic.mitm-ca-password=test-mitm-ca-password-1d6ad9b95b76490e",
      "toolbox.traffic.mitm-enabled=false",
      "toolbox.vulnerability-catalog.nuclei.import-on-startup=false",
      "toolbox.vulnerability-catalog.scanner-pocs.import-on-startup=false"
    })
@AutoConfigureMockMvc
class CorsOriginAllowlistTests {
  @Autowired private MockMvc mockMvc;

  private void preflight(String origin) throws Exception {
    mockMvc
        .perform(
            options("/api/auth/login")
                .header(HttpHeaders.ORIGIN, origin)
                .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "POST"))
        .andExpect(status().isOk());
  }

  @Test
  void 第三方网站不得获得CORS授权() throws Exception {
    mockMvc
        .perform(
            options("/api/auth/login")
                .header(HttpHeaders.ORIGIN, "https://evil.example")
                .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "POST"))
        .andExpect(status().isForbidden())
        .andExpect(header().doesNotExist(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN));
  }

  @Test
  void 本地开发来源必须保留CORS授权() throws Exception {
    mockMvc
        .perform(
            options("/api/auth/login")
                .header(HttpHeaders.ORIGIN, "http://127.0.0.1:5173")
                .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "POST"))
        .andExpect(status().isOk())
        .andExpect(
            header().string(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, "http://127.0.0.1:5173"));
  }

  @Test
  void 桌面file来源必须保留CORS授权() throws Exception {
    mockMvc
        .perform(
            options("/api/auth/login")
                .header(HttpHeaders.ORIGIN, "file://")
                .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "POST"))
        .andExpect(status().isOk())
        .andExpect(header().string(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, "file://"));
  }
}
