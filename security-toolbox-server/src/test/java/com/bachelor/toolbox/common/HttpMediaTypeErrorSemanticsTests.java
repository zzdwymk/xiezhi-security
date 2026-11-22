package com.bachelor.toolbox.common;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.bachelor.toolbox.auth.JwtService;
import com.bachelor.toolbox.auth.User;
import com.bachelor.toolbox.auth.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

/**
 * 第296轮：客户端用了不支持的 Content-Type 时必须是 415，而不是 500。
 *
 * <p>请求体声明为 {@code text/plain} 时 Spring 抛 {@code HttpMediaTypeNotSupportedException}；
 * 全局异常处理没有对应分支，落进兜底 500。与 R295 的 405 同类：把客户端用法错误记成服务端故障。
 */
@SpringBootTest(
    properties = {
      "spring.datasource.url=jdbc:h2:mem:http-media-type-semantics;MODE=PostgreSQL;DB_CLOSE_DELAY=-1",
      "spring.jpa.hibernate.ddl-auto=create-drop",
      "toolbox.auth.allow-insecure-development-credentials=true",
      "toolbox.traffic.mitm-enabled=false",
      "toolbox.vulnerability-catalog.nuclei.import-on-startup=false",
      "toolbox.vulnerability-catalog.cisa-kev-enabled=false"
    })
@AutoConfigureMockMvc
class HttpMediaTypeErrorSemanticsTests {
  @Autowired MockMvc mvc;
  @Autowired UserRepository users;
  @Autowired JwtService jwt;

  @Test
  void unsupportedContentTypeReturns415NotServerError() throws Exception {
    User admin = users.findByUsername("admin").orElseThrow();
    String token = jwt.createToken(admin);

    mvc.perform(
            post("/api/tasks")
                .header("Authorization", "Bearer " + token)
                .contentType(MediaType.TEXT_PLAIN)
                .content("not-json"))
        .andExpect(status().isUnsupportedMediaType())
        .andExpect(jsonPath("$.message").value("请求体类型不支持"));
  }
}
