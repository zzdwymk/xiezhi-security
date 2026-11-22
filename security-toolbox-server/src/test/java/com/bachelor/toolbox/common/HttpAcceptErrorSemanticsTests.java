package com.bachelor.toolbox.common;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
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
 * 第298轮：客户端只接受无法提供的媒体类型时必须返回 406，而不是 500。
 *
 * <p>请求 {@code Accept: application/xml} 时 Spring 抛 {@code HttpMediaTypeNotAcceptableException}；
 * 全局异常处理没有对应分支，落进兜底 500，且因客户端不接受 JSON 响应体为空——客户端既拿不到状态语义，
 * 也拿不到任何说明。与 R295(405) / R296(415) 同族。
 */
@SpringBootTest(
    properties = {
      "spring.datasource.url=jdbc:h2:mem:http-accept-semantics;MODE=PostgreSQL;DB_CLOSE_DELAY=-1",
      "spring.jpa.hibernate.ddl-auto=create-drop",
      "toolbox.auth.allow-insecure-development-credentials=true",
      "toolbox.traffic.mitm-enabled=false",
      "toolbox.vulnerability-catalog.nuclei.import-on-startup=false",
      "toolbox.vulnerability-catalog.cisa-kev-enabled=false"
    })
@AutoConfigureMockMvc
class HttpAcceptErrorSemanticsTests {
  @Autowired MockMvc mvc;
  @Autowired UserRepository users;
  @Autowired JwtService jwt;

  @Test
  void unacceptableAcceptHeaderReturns406NotServerError() throws Exception {
    User admin = users.findByUsername("admin").orElseThrow();
    String token = jwt.createToken(admin);

    mvc.perform(
            get("/api/targets")
                .header("Authorization", "Bearer " + token)
                .accept(MediaType.APPLICATION_XML))
        .andExpect(status().isNotAcceptable());
  }
}
