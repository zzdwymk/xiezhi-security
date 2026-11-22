package com.bachelor.toolbox.recon;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
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
 * 第306轮：字典导入的请求体必须有声明式大小上限。
 *
 * <p>{@code TextImportRequest} 原本没有任何校验注解，且 {@code importText} 先 {@code parseLines(text)}
 * 把整段文本切成列表、之后才检查 100000 条上限——一份超大文本会在"上限检查"之前就被完整展开，
 * 造成内存放大。入口应当先按字符数拒绝。
 */
@SpringBootTest(
    properties = {
      "spring.datasource.url=jdbc:h2:mem:dict-import-limit;MODE=PostgreSQL;DB_CLOSE_DELAY=-1",
      "spring.jpa.hibernate.ddl-auto=create-drop",
      "toolbox.auth.allow-insecure-development-credentials=true",
      "toolbox.traffic.mitm-enabled=false",
      "toolbox.vulnerability-catalog.nuclei.import-on-startup=false",
      "toolbox.vulnerability-catalog.cisa-kev-enabled=false"
    })
@AutoConfigureMockMvc
class PathDictionaryImportLimitTests {
  @Autowired MockMvc mvc;
  @Autowired UserRepository users;
  @Autowired JwtService jwt;

  @Test
  void oversizedImportTextIsRejectedAtTheBoundary() throws Exception {
    User admin = users.findByUsername("admin").orElseThrow();
    String token = jwt.createToken(admin);
    String huge = "a".repeat(2_100_000);
    String body = "{\"text\":\"" + huge + "\"}";

    mvc.perform(
            post("/api/recon/path-dictionary/import")
                .header("Authorization", "Bearer " + token)
                .contentType(MediaType.APPLICATION_JSON)
                .content(body))
        .andExpect(status().isBadRequest());
  }
}
