package com.bachelor.toolbox.ai.guard;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.bachelor.toolbox.auth.User;
import com.bachelor.toolbox.auth.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;

/**
 * Round 229：能力审批端点必须只允许管理员访问。
 *
 * <p>普通 USER 如果能调用 `/api/ai/guard/approvals/grant`，就能自行批准 Agent 提出的高风险能力
 * 申请，绕过“用户在确认卡片上逐次确认”的授权边界。
 */
@SpringBootTest(
    properties = {
      "spring.datasource.url=jdbc:h2:mem:capability-approval-auth-test;MODE=PostgreSQL;DB_CLOSE_DELAY=-1",
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
class CapabilityApprovalAuthorizationTests {
  private static final String VIEWER_PASSWORD = "{{SECRET_3m7j5v2q}}";

  @Autowired private MockMvc mockMvc;
  @Autowired private UserRepository users;
  @Autowired private PasswordEncoder encoder;
  @Autowired private ObjectMapper objectMapper;

  @BeforeEach
  void createOrdinaryUser() {
    User viewer =
        users.findByUsername("approval-viewer").orElseGet(
            () -> {
              User user = new User();
              user.setUsername("approval-viewer");
              user.setRole("USER");
              user.setEnabled(true);
              return user;
            });
    viewer.setPasswordHash(encoder.encode(VIEWER_PASSWORD));
    users.save(viewer);
  }

  private String login(String username, String password) throws Exception {
    String body =
        mockMvc
            .perform(
                post("/api/auth/login")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(
                        objectMapper.writeValueAsString(
                            Map.of("username", username, "password", password))))
            .andExpect(status().isOk())
            .andReturn()
            .getResponse()
            .getContentAsString();
    return objectMapper.readTree(body).path("token").asText();
  }

  @Test
  void 普通用户不能读取待批能力申请() throws Exception {
    String viewerToken = login("approval-viewer", VIEWER_PASSWORD);
    mockMvc
        .perform(
            get("/api/ai/guard/approvals/pending")
                .header("Authorization", "Bearer " + viewerToken))
        .andExpect(status().isForbidden());
  }

  @Test
  void 普通用户不能批准能力申请() throws Exception {
    String viewerToken = login("approval-viewer", VIEWER_PASSWORD);
    mockMvc
        .perform(
            post("/api/ai/guard/approvals/grant")
                .header("Authorization", "Bearer " + viewerToken)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"capabilityCode\":\"x\",\"parameterDigest\":\"y\"}"))
        .andExpect(status().isForbidden());
  }

  @Test
  void 管理员仍可读取待批能力申请() throws Exception {
    String adminToken = login("admin", "test-admin-password-7bbbe095d8724fcb");
    mockMvc
        .perform(
            get("/api/ai/guard/approvals/pending")
                .header("Authorization", "Bearer " + adminToken))
        .andExpect(status().isOk());
  }
}
