package com.bachelor.toolbox.settings;

import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.bachelor.toolbox.auth.JwtService;
import com.bachelor.toolbox.auth.User;
import com.bachelor.toolbox.auth.UserRepository;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest(
    properties = {
      "spring.datasource.url=jdbc:h2:mem:settings-security;MODE=PostgreSQL;DB_CLOSE_DELAY=-1",
      "spring.jpa.hibernate.ddl-auto=create-drop",
      "toolbox.auth.admin-password=test-admin-password-7bbbe095d8724fcb",
      "toolbox.auth.jwt-secret=test-jwt-secret-cdc24d415ad843aa9ef313028ae9be30",
      "toolbox.traffic.mitm-enabled=false",
      "toolbox.vulnerability-catalog.nuclei.import-on-startup=false",
      "toolbox.vulnerability-catalog.cisa-kev-enabled=false"
    })
@AutoConfigureMockMvc
class SettingsSecurityTests {
  @Autowired private MockMvc mockMvc;
  @Autowired private UserRepository users;
  @Autowired private JwtService jwt;
  @MockBean private BusinessDataResetService resetService;

  @Test
  void clearDataRequiresAnAuthenticatedAdministrator() throws Exception {
    mockMvc.perform(clearRequest(null)).andExpect(status().isUnauthorized());

    User regular = new User();
    regular.setUsername("settings-user");
    regular.setPasswordHash("unused-test-hash");
    regular.setRole("USER");
    regular = users.save(regular);
    mockMvc.perform(clearRequest(jwt.createToken(regular))).andExpect(status().isForbidden());
    verify(resetService, never()).clear("CLEAR");

    User admin = users.findByUsername("admin").orElseThrow();
    when(resetService.clear("CLEAR"))
        .thenReturn(
            new BusinessDataResetService.ResetResult(Instant.now(), 0, true, 0, 0));
    mockMvc.perform(clearRequest(jwt.createToken(admin))).andExpect(status().isOk());
    verify(resetService).clear("CLEAR");
  }

  private org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder clearRequest(
      String token) {
    var request =
        delete("/api/settings/data")
            .contentType(MediaType.APPLICATION_JSON)
            .content("{\"confirmation\":\"CLEAR\"}");
    return token == null ? request : request.header("Authorization", "Bearer " + token);
  }
}
