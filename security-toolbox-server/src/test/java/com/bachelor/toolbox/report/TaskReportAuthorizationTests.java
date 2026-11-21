package com.bachelor.toolbox.report;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.bachelor.toolbox.auth.JwtService;
import com.bachelor.toolbox.auth.User;
import com.bachelor.toolbox.auth.UserRepository;
import com.bachelor.toolbox.project.AssessmentProject;
import com.bachelor.toolbox.project.AssessmentProjectRepository;
import com.bachelor.toolbox.task.SecurityTask;
import com.bachelor.toolbox.task.SecurityTaskRepository;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

/**
 * 第278轮：任务报告接口的横向授权回归。
 *
 * <p>{@code GET /api/reports/tasks/**} 只要求登录，因此项目归属必须由服务层的
 * {@code TaskService.get → AssessmentProjectService.get → requireAccess} 保证。本测试用真实
 * Spring 安全链路锁定该行为：他人项目的任务报告不得返回成功响应体。
 */
@SpringBootTest(
    properties = {
      "spring.datasource.url=jdbc:h2:mem:report-authorization;MODE=PostgreSQL;DB_CLOSE_DELAY=-1",
      "spring.jpa.hibernate.ddl-auto=create-drop",
      "toolbox.auth.admin-password=test-admin-password-7bbbe095d8724fcb",
      "toolbox.auth.jwt-secret=test-jwt-secret-cdc24d415ad843aa9ef313028ae9be30",
      "toolbox.traffic.mitm-enabled=false",
      "toolbox.vulnerability-catalog.nuclei.import-on-startup=false",
      "toolbox.vulnerability-catalog.cisa-kev-enabled=false"
    })
@AutoConfigureMockMvc
class TaskReportAuthorizationTests {
  @Autowired private MockMvc mockMvc;
  @Autowired private UserRepository users;
  @Autowired private JwtService jwt;
  @Autowired private AssessmentProjectRepository projects;
  @Autowired private SecurityTaskRepository tasks;

  @Test
  void normalUserCannotReadAnotherOwnersTaskReport() throws Exception {
    String foreignTaskId = seedForeignProjectWithTask();
    String token = tokenFor("report-outsider", "USER");

    mockMvc
        .perform(
            get("/api/reports/tasks/{id}.html", foreignTaskId)
                .accept(MediaType.TEXT_HTML)
                .header("Authorization", "Bearer " + token))
        .andExpect(status().isBadRequest());

    mockMvc
        .perform(
            get("/api/reports/tasks/{id}/download", foreignTaskId)
                .header("Authorization", "Bearer " + token))
        .andExpect(status().isBadRequest());
  }

  @Test
  void anonymousCallerCannotReadTaskReport() throws Exception {
    String foreignTaskId = seedForeignProjectWithTask();
    mockMvc
        .perform(get("/api/reports/tasks/{id}.html", foreignTaskId).accept(MediaType.TEXT_HTML))
        .andExpect(status().isUnauthorized());
  }

  @Test
  void ownerCanReadOwnTaskReport() throws Exception {
    AssessmentProject mine = project("report-insider");
    SecurityTask task = task(mine.getId());
    String token = tokenFor("report-insider", "USER");

    mockMvc
        .perform(
            get("/api/reports/tasks/{id}.html", task.getId())
                .accept(MediaType.TEXT_HTML)
                .header("Authorization", "Bearer " + token))
        .andExpect(status().isOk());
  }

  private String seedForeignProjectWithTask() {
    AssessmentProject foreign = project("report-someone-else");
    return String.valueOf(task(foreign.getId()).getId());
  }

  private AssessmentProject project(String owner) {
    AssessmentProject project = new AssessmentProject();
    project.setName(owner + " project");
    project.setOwner(owner);
    project.setStatus("ACTIVE");
    project.setAuthorizationStatement("test authorization");
    project.setAuthorizationValidFrom(Instant.now().minusSeconds(3600));
    project.setAuthorizationExpiresAt(Instant.now().plusSeconds(3600));
    return projects.saveAndFlush(project);
  }

  private SecurityTask task(Long projectId) {
    SecurityTask task = new SecurityTask();
    task.setProjectId(projectId);
    task.setTargetId(1L);
    task.setToolCode("http_headers");
    task.setStatus("SUCCESS");
    task.setProgress(100);
    return tasks.saveAndFlush(task);
  }

  private String tokenFor(String username, String role) {
    User user = new User();
    user.setUsername(username);
    user.setPasswordHash("unused-test-hash");
    user.setRole(role);
    return jwt.createToken(users.save(user));
  }
}