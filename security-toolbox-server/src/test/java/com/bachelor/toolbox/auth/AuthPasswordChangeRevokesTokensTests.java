package com.bachelor.toolbox.auth;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

/**
 * Round 224：修改密码后，旧 JWT 必须立即失效；新密码登录必须正常。
 *
 * <p>使用独立内存库，避免影响其它 Spring 测试上下文中的管理员口令。
 */
@SpringBootTest(
    properties = {
      "spring.datasource.url=jdbc:h2:mem:auth-token-revocation-test;MODE=PostgreSQL;DB_CLOSE_DELAY=-1",
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
class AuthPasswordChangeRevokesTokensTests {
  private static final String OLD_PASSWORD = "test-admin-password-7bbbe095d8724fcb";
  private static final String NEW_PASSWORD = "Round224-Strong-Pass!";

  @Autowired private MockMvc mockMvc;
  @Autowired private ObjectMapper objectMapper;

  private String login(String password) throws Exception {
    String response =
        mockMvc
            .perform(
                post("/api/auth/login")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(
                        objectMapper.writeValueAsString(
                            Map.of("username", "admin", "password", password))))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.token").isString())
            .andReturn()
            .getResponse()
            .getContentAsString();
    return objectMapper.readTree(response).path("token").asText();
  }

  @Test
  void 修改密码后旧令牌必须被拒绝且新密码可重新登录() throws Exception {
    String oldToken = login(OLD_PASSWORD);

    mockMvc
        .perform(get("/api/auth/me").header("Authorization", "Bearer " + oldToken))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.username").value("admin"));

    mockMvc
        .perform(
            post("/api/auth/change-password")
                .header("Authorization", "Bearer " + oldToken)
                .contentType(MediaType.APPLICATION_JSON)
                .content(
                    objectMapper.writeValueAsString(
                        Map.of("currentPassword", OLD_PASSWORD, "newPassword", NEW_PASSWORD))))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.changed").value(true));

    // 修复目标：修改密码后，旧 JWT 不应再访问受保护接口。
    mockMvc
        .perform(get("/api/auth/me").header("Authorization", "Bearer " + oldToken))
        .andExpect(status().isUnauthorized());

    // 新密码登录必须正常，并签发可用的新令牌。
    String newToken = login(NEW_PASSWORD);
    mockMvc
        .perform(get("/api/auth/me").header("Authorization", "Bearer " + newToken))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.username").value("admin"));
  }
}
