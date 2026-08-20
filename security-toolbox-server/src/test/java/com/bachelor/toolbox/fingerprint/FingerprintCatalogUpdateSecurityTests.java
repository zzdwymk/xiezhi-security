package com.bachelor.toolbox.fingerprint;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.bachelor.toolbox.auth.JwtService;
import com.bachelor.toolbox.auth.User;
import com.bachelor.toolbox.auth.UserRepository;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.UUID;
import org.junit.jupiter.api.AfterAll;
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
      "spring.datasource.url=jdbc:h2:mem:fingerprint-update-security;MODE=PostgreSQL;DB_CLOSE_DELAY=-1",
      "spring.jpa.hibernate.ddl-auto=create-drop",
      "toolbox.auth.admin-password=test-admin-password-fingerprint-update",
      "toolbox.auth.jwt-secret=test-jwt-secret-fingerprint-update-security-2026",
      "toolbox.traffic.mitm-enabled=false",
      "toolbox.vulnerability-catalog.nuclei.import-on-startup=false",
      "toolbox.vulnerability-catalog.cisa-kev-enabled=false"
    })
@AutoConfigureMockMvc
class FingerprintCatalogUpdateSecurityTests {
  private static final String INITIAL_CATALOG =
      """
      {
        "version": "security-initial",
        "rules": [
          {
            "id": "security-initial-rule",
            "name": "Security initial rule",
            "category": "TEST",
            "confidence": 80,
            "body": ["initial-marker"]
          }
        ]
      }
      """;

  private static final String UPDATED_CATALOG =
      """
      {
        "version": "security-updated",
        "rules": [
          {
            "id": "security-updated-rule",
            "name": "Security updated rule",
            "category": "TEST",
            "confidence": 90,
            "title": ["updated-marker"]
          }
        ]
      }
      """;

  private static final Path RULES_FILE = createInitialRulesFile();

  @Autowired private MockMvc mockMvc;
  @Autowired private UserRepository users;
  @Autowired private JwtService jwt;
  @Autowired private ObjectMapper objectMapper;

  @DynamicPropertySource
  static void fingerprintProperties(DynamicPropertyRegistry registry) {
    registry.add("toolbox.fingerprints.rules-file", () -> RULES_FILE.toString());
  }

  @AfterAll
  static void removeTestRulesFile() throws IOException {
    Files.deleteIfExists(RULES_FILE);
  }

  @Test
  void catalogUpdateRequiresAnAuthenticatedAdministratorAndPersistsValidCatalog()
      throws Exception {
    String initialBytes = Files.readString(RULES_FILE, StandardCharsets.UTF_8);

    mockMvc.perform(updateRequest(null)).andExpect(status().isUnauthorized());
    assertThat(Files.readString(RULES_FILE, StandardCharsets.UTF_8)).isEqualTo(initialBytes);

    User regular = new User();
    regular.setUsername("fingerprint-update-user");
    regular.setPasswordHash("unused-test-hash");
    regular.setRole("USER");
    regular = users.save(regular);
    String regularToken = jwt.createToken(regular);

    mockMvc.perform(updateRequest(regularToken)).andExpect(status().isForbidden());
    assertThat(Files.readString(RULES_FILE, StandardCharsets.UTF_8)).isEqualTo(initialBytes);

    User admin = users.findByUsername("admin").orElseThrow();
    mockMvc
        .perform(updateRequest(jwt.createToken(admin)))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.version").value("security-updated"))
        .andExpect(jsonPath("$.sha256").isString())
        .andExpect(jsonPath("$.ruleCount").value(1))
        .andExpect(jsonPath("$.source").value("EXTERNAL"));

    JsonNode storedCatalog = objectMapper.readTree(RULES_FILE.toFile());
    assertThat(storedCatalog.path("version").asText()).isEqualTo("security-updated");
    assertThat(storedCatalog.path("rules").path(0).path("id").asText())
        .isEqualTo("security-updated-rule");

    mockMvc
        .perform(
            get("/api/fingerprints/catalog")
                .header("Authorization", "Bearer " + regularToken))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.version").value("security-updated"))
        .andExpect(jsonPath("$.ruleCount").value(1));
  }

  @Test
  void catalogReloadAlsoRequiresAnAuthenticatedAdministrator() throws Exception {
    mockMvc.perform(reloadRequest(null)).andExpect(status().isUnauthorized());

    User regular = new User();
    regular.setUsername("fingerprint-reload-user");
    regular.setPasswordHash("unused-test-hash");
    regular.setRole("USER");
    regular = users.save(regular);
    mockMvc
        .perform(reloadRequest(jwt.createToken(regular)))
        .andExpect(status().isForbidden());

    User admin = users.findByUsername("admin").orElseThrow();
    mockMvc
        .perform(reloadRequest(jwt.createToken(admin)))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.version").isString())
        .andExpect(jsonPath("$.sha256").isString())
        .andExpect(jsonPath("$.ruleCount").isNumber())
        .andExpect(jsonPath("$.source").value("EXTERNAL"));
  }

  private MockHttpServletRequestBuilder updateRequest(String token) {
    MockHttpServletRequestBuilder request =
        put("/api/fingerprints/catalog")
            .contentType(MediaType.APPLICATION_JSON)
            .content(UPDATED_CATALOG);
    return token == null ? request : request.header("Authorization", "Bearer " + token);
  }

  private MockHttpServletRequestBuilder reloadRequest(String token) {
    MockHttpServletRequestBuilder request = post("/api/fingerprints/catalog/reload");
    return token == null ? request : request.header("Authorization", "Bearer " + token);
  }

  private static Path createInitialRulesFile() {
    try {
      Path targetDirectory = Path.of("target", "test-data").toAbsolutePath().normalize();
      Files.createDirectories(targetDirectory);
      Path rulesFile =
          targetDirectory.resolve("fingerprint-update-security-" + UUID.randomUUID() + ".json");
      return Files.writeString(
          rulesFile,
          INITIAL_CATALOG,
          StandardCharsets.UTF_8,
          StandardOpenOption.CREATE_NEW,
          StandardOpenOption.WRITE);
    } catch (IOException ex) {
      throw new ExceptionInInitializerError(ex);
    }
  }
}
