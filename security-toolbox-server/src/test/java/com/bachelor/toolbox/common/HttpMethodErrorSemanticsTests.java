package com.bachelor.toolbox.common;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
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
 * 第295轮：客户端用错 HTTP 方法时必须是 405，而不是 500。
 *
 * <p>{@code /api/targets/{id}}、{@code /api/findings/{id}} 只有 PUT/DELETE，没有 GET。
 * 请求这类路径会抛 {@code HttpRequestMethodNotSupportedException}，而全局异常处理没有对应分支，
 * 最终落到兜底 500「服务器处理失败」——把客户端的用法错误记成服务端故障，污染告警且在监控上
 * 掩盖真实故障。
 */
@SpringBootTest(
    properties = {
      "spring.datasource.url=jdbc:h2:mem:http-method-semantics;MODE=PostgreSQL;DB_CLOSE_DELAY=-1",
      "spring.jpa.hibernate.ddl-auto=create-drop",
      "toolbox.auth.allow-insecure-development-credentials=true",
      "toolbox.traffic.mitm-enabled=false",
      "toolbox.vulnerability-catalog.nuclei.import-on-startup=false",
      "toolbox.vulnerability-catalog.cisa-kev-enabled=false"
    })
@AutoConfigureMockMvc
class HttpMethodErrorSemanticsTests {
  @Autowired MockMvc mvc;
  @Autowired UserRepository users;
  @Autowired JwtService jwt;

  @Test
  void unsupportedMethodOnExistingPathReturns405NotServerError() throws Exception {
    User admin = users.findByUsername("admin").orElseThrow();
    String token = jwt.createToken(admin);

    mvc.perform(get("/api/targets/1").header("Authorization", "Bearer " + token))
        .andExpect(status().isMethodNotAllowed())
        .andExpect(jsonPath("$.message").value("请求方法不支持"));

    mvc.perform(get("/api/findings/1").header("Authorization", "Bearer " + token))
        .andExpect(status().isMethodNotAllowed());
  }
}
