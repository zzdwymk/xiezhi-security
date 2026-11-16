package com.bachelor.toolbox.audit;

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

@SpringBootTest(properties = {
    "spring.datasource.url=jdbc:h2:mem:audit-access-security;MODE=PostgreSQL;DB_CLOSE_DELAY=-1",
    "spring.jpa.hibernate.ddl-auto=create-drop",
    "toolbox.auth.allow-insecure-development-credentials=true",
    "toolbox.traffic.mitm-enabled=false",
    "toolbox.vulnerability-catalog.nuclei.import-on-startup=false",
    "toolbox.vulnerability-catalog.cisa-kev-enabled=false"
})
@AutoConfigureMockMvc
class AuditControllerSecurityTests {
  @Autowired MockMvc mvc;
  @Autowired UserRepository users;
  @Autowired JwtService jwt;

  @Test
  void globalAndProjectFilteredAuditLogsRequireAdministrator() throws Exception {
    mvc.perform(get("/api/audits")).andExpect(status().isUnauthorized());
    User user = new User();
    user.setUsername("audit-regular-user");
    user.setPasswordHash("unused-test-hash");
    user.setRole("USER");
    String token = jwt.createToken(users.save(user));
    for (String url : new String[] {"/api/audits", "/api/audits?projectId=1", "/api/audits?projectId=0"}) {
      mvc.perform(get(url).header("Authorization", "Bearer " + token))
          .andExpect(status().isForbidden());
    }
    User admin = users.findByUsername("admin").orElseThrow();
    mvc.perform(get("/api/audits").header("Authorization", "Bearer " + jwt.createToken(admin)))
        .andExpect(status().isOk());
  }
}
