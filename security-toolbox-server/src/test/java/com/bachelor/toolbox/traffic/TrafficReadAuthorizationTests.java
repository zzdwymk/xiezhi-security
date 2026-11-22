package com.bachelor.toolbox.traffic;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.bachelor.toolbox.auth.JwtService;
import com.bachelor.toolbox.auth.User;
import com.bachelor.toolbox.auth.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

/**
 * 第294轮：抓包数据是全平台共享的敏感内容（含 Cookie / Authorization / 请求体）。
 *
 * <p>写操作（POST/PUT/DELETE /api/traffic/**）在 SecurityConfig 里已限管理员，前端
 * Findings.vue / Tasks.vue 也用 {@code role === "ADMIN"} 决定是否允许查看抓包——但读接口
 * 从未限制角色，导致任何登录用户都能读取全部抓包。本测试锁定「读也必须管理员」。
 */
@SpringBootTest(
    properties = {
      "spring.datasource.url=jdbc:h2:mem:traffic-read-security;MODE=PostgreSQL;DB_CLOSE_DELAY=-1",
      "spring.jpa.hibernate.ddl-auto=create-drop",
      "toolbox.auth.allow-insecure-development-credentials=true",
      "toolbox.traffic.mitm-enabled=false",
      "toolbox.vulnerability-catalog.nuclei.import-on-startup=false",
      "toolbox.vulnerability-catalog.cisa-kev-enabled=false"
    })
@AutoConfigureMockMvc
class TrafficReadAuthorizationTests {
  @Autowired MockMvc mvc;
  @Autowired UserRepository users;
  @Autowired JwtService jwt;

  @Test
  void readingCapturedTrafficRequiresAdministrator() throws Exception {
    mvc.perform(get("/api/traffic/sessions")).andExpect(status().isUnauthorized());

    User user = new User();
    user.setUsername("traffic-regular-user");
    user.setPasswordHash("unused-test-hash");
    user.setRole("USER");
    String token = jwt.createToken(users.save(user));

    for (String url :
        new String[] {
          "/api/traffic/sessions",
          "/api/traffic/packets/1",
          "/api/traffic/scans",
          "/api/traffic/scans/recent",
          "/api/traffic/status",
          "/api/traffic/filters"
        }) {
      mvc.perform(get(url).header("Authorization", "Bearer " + token))
          .andExpect(status().isForbidden());
    }

    User admin = users.findByUsername("admin").orElseThrow();
    mvc.perform(get("/api/traffic/sessions").header("Authorization", "Bearer " + jwt.createToken(admin)))
        .andExpect(status().isOk());
  }
}
