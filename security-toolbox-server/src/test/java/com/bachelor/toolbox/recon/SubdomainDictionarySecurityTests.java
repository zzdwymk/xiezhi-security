package com.bachelor.toolbox.recon;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.bachelor.toolbox.auth.JwtService;
import com.bachelor.toolbox.auth.User;
import com.bachelor.toolbox.auth.UserRepository;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

@SpringBootTest(
    properties = {
      "spring.datasource.url=jdbc:h2:mem:subdomain-dict-security;MODE=PostgreSQL;DB_CLOSE_DELAY=-1",
      "spring.jpa.hibernate.ddl-auto=create-drop",
      "toolbox.auth.admin-password=test-admin-password-subdomain-dict",
      "toolbox.auth.jwt-secret=test-jwt-secret-subdomain-dict-security-2026",
      "toolbox.traffic.mitm-enabled=false",
      "toolbox.vulnerability-catalog.nuclei.import-on-startup=false",
      "toolbox.vulnerability-catalog.cisa-kev-enabled=false"
    })
@AutoConfigureMockMvc
class SubdomainDictionarySecurityTests {
  private static final Path MANAGED_FILE =
      Path.of("target", "test-data", "subdomain-dict-security-" + System.nanoTime() + ".txt");
  private static final String SUFFIX =
      java.util.concurrent.ThreadLocalRandom.current().nextInt(1_000_000, Integer.MAX_VALUE)
          + "";
  private static final String WORD_A = "dicta" + SUFFIX;
  private static final String WORD_B = "dictb" + SUFFIX;

  @Autowired private MockMvc mockMvc;
  @Autowired private UserRepository users;
  @Autowired private JwtService jwt;

  @DynamicPropertySource
  static void dictProperties(DynamicPropertyRegistry registry) {
    registry.add("toolbox.recon.subdomain-dictionary-file", () -> MANAGED_FILE.toString());
  }

  @AfterAll
  static void removeManagedFile() throws Exception {
    Files.deleteIfExists(MANAGED_FILE);
  }

  @BeforeEach
  void cleanManagedFile() throws Exception {
    Files.deleteIfExists(MANAGED_FILE);
  }

  @Test
  void dictionaryMutationsRequireAdministrator() throws Exception {
    mockMvc
        .perform(importRequest(null))
        .andExpect(status().isUnauthorized());
    mockMvc
        .perform(updateRequest(null))
        .andExpect(status().isUnauthorized());

    User regular = new User();
    regular.setUsername("subdomain-dict-user");
    regular.setPasswordHash("unused-test-hash");
    regular.setRole("USER");
    regular = users.save(regular);
    String regularToken = jwt.createToken(regular);

    mockMvc
        .perform(importRequest(regularToken))
        .andExpect(status().isForbidden());
    mockMvc
        .perform(updateRequest(regularToken))
        .andExpect(status().isForbidden());

    User admin = users.findByUsername("admin").orElseThrow();
    String adminToken = jwt.createToken(admin);
    mockMvc
        .perform(importRequest(adminToken))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.imported").value(2))
        .andExpect(jsonPath("$.duplicates").value(0))
        .andExpect(jsonPath("$.invalid").value(1));
    assertThat(Files.exists(MANAGED_FILE)).isTrue();
  }

  @Test
  void viewAndValidateAreReadableByUsers() throws Exception {
    User regular = new User();
    regular.setUsername("subdomain-dict-viewer");
    regular.setPasswordHash("unused-test-hash");
    regular.setRole("USER");
    regular = users.save(regular);
    String token = jwt.createToken(regular);

    mockMvc
        .perform(get("/api/recon/subdomain-dictionary").header("Authorization", "Bearer " + token))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.source").isString())
        .andExpect(jsonPath("$.wordCount").isNumber());

    mockMvc
        .perform(
            post("/api/recon/subdomain-dictionary/validate")
                .header("Authorization", "Bearer " + token)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"words\":[\"ok\",\"bad dot\"]}"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.length()").value(1));
  }

  private MockHttpServletRequestBuilder importRequest(String token) {
    MockHttpServletRequestBuilder request =
        post("/api/recon/subdomain-dictionary/import")
            .contentType(MediaType.APPLICATION_JSON)
            .content("{\"text\":\"" + WORD_A + "\\n" + WORD_B + "\\nbad.domain\\n\"}");
    return token == null ? request : request.header("Authorization", "Bearer " + token);
  }

  private MockHttpServletRequestBuilder updateRequest(String token) {
    MockHttpServletRequestBuilder request =
        post("/api/recon/subdomain-dictionary/update")
            .contentType(MediaType.APPLICATION_JSON)
            .content("{\"additions\":[\"gamma\"],\"removals\":[]}");
    return token == null ? request : request.header("Authorization", "Bearer " + token);
  }
}