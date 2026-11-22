package com.bachelor.toolbox.task;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
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
 * 第301轮：全局任务并发上限是平台级配置，必须只有管理员能改。
 *
 * <p>{@code PUT /api/tasks/control/limits} 未被任何安全规则匹配，落到 {@code /api/**} 的
 * "仅需登录"分支。普通用户因此可以把并发上限压到 1（让所有人的任务长期排队）或拉到 32
 * （放大资源占用）。其它平台级配置（扫描计划、抓包过滤器、依赖探测）均为管理员专属。
 */
@SpringBootTest(
    properties = {
      "spring.datasource.url=jdbc:h2:mem:task-limit-authorization;MODE=PostgreSQL;DB_CLOSE_DELAY=-1",
      "spring.jpa.hibernate.ddl-auto=create-drop",
      "toolbox.auth.allow-insecure-development-credentials=true",
      "toolbox.traffic.mitm-enabled=false",
      "toolbox.vulnerability-catalog.nuclei.import-on-startup=false",
      "toolbox.vulnerability-catalog.cisa-kev-enabled=false"
    })
@AutoConfigureMockMvc
class TaskLimitAuthorizationTests {
  @Autowired MockMvc mvc;
  @Autowired UserRepository users;
  @Autowired JwtService jwt;

  @Test
  void ordinaryUserCannotChangeGlobalConcurrencyLimit() throws Exception {
    User user = new User();
    user.setUsername("task-limit-regular-user");
    user.setPasswordHash("unused-test-hash");
    user.setRole("USER");
    String token = jwt.createToken(users.save(user));

    mvc.perform(
            put("/api/tasks/control/limits")
                .header("Authorization", "Bearer " + token)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"maxConcurrentTasks\":1}"))
        .andExpect(status().isForbidden());

    User admin = users.findByUsername("admin").orElseThrow();
    mvc.perform(
            put("/api/tasks/control/limits")
                .header("Authorization", "Bearer " + jwt.createToken(admin))
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"maxConcurrentTasks\":3}"))
        .andExpect(status().isOk());
  }
}
