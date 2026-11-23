package com.bachelor.toolbox.schedule;

import static org.assertj.core.api.Assertions.assertThat;

import com.bachelor.toolbox.auth.User;
import com.bachelor.toolbox.auth.UserRepository;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.annotation.DirtiesContext;

/**
 * Real HTTP authorization regression: login -> projects -> targets -> schedules -> owner reads and
 * rejected mutations -> administrator lifecycle. No mocked controller, JWT, service or repository.
 *
 * <p>The product has no account-registration endpoint. Only fixture accounts are seeded into this
 * isolated in-memory database; every authentication and business operation uses the actual API.
 * The schedules remain disabled except for the administrator enable/disable check, with an interval
 * of one hour, so this authorization test never dispatches an external scan during regression.
 */
@SpringBootTest(
    webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
    properties = {
      "spring.datasource.url=jdbc:h2:mem:schedule-auth-http-r366;MODE=PostgreSQL;DB_CLOSE_DELAY=-1",
      "spring.jpa.hibernate.ddl-auto=create-drop",
      "toolbox.auth.allow-insecure-development-credentials=true",
      "toolbox.traffic.mitm-enabled=false",
      "toolbox.vulnerability-catalog.nuclei.import-on-startup=false",
      "toolbox.vulnerability-catalog.cisa-kev-enabled=false",
      "toolbox.ai.enabled=false",
      "toolbox.ai.runtime-enabled=false"
    })
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
class ScanScheduleAuthorizationHttpEndToEndTests {
  @LocalServerPort private int port;
  @Autowired private UserRepository users;
  @Autowired private PasswordEncoder encoder;
  @Autowired private ObjectMapper mapper;
  private final HttpClient client =
      HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();

  @Test
  void realOwnerLoginsCannotReadForeignPlansOrMutateAnyPlan() throws Exception {
    String suffix = UUID.randomUUID().toString().substring(0, 8);
    String admin = "r366_admin_" + suffix;
    String alice = "r366_alice_" + suffix;
    String bob = "r366_bob_" + suffix;
    String password = UUID.randomUUID().toString() + "!R366";
    seedAccount(admin, "ADMIN", password);
    seedAccount(alice, "USER", password);
    seedAccount(bob, "USER", password);

    String adminToken = login(admin, password, "ADMIN");
    String aliceToken = login(alice, password, "USER");
    String bobToken = login(bob, password, "USER");
    long projectA = createProject(adminToken, alice, "A-" + suffix);
    long projectB = createProject(adminToken, bob, "B-" + suffix);
    long targetA = createTarget(adminToken, projectA, suffix + "-a");
    long targetB = createTarget(adminToken, projectB, suffix + "-b");
    Map<String, Object> planA = scheduleRequest(projectA, targetA);
    Response createdA = request("POST", "/scan-schedules", adminToken, planA);
    Response createdB =
        request("POST", "/scan-schedules", adminToken, scheduleRequest(projectB, targetB));
    assertThat(createdA.status()).isEqualTo(201);
    assertThat(createdB.status()).isEqualTo(201);
    long scheduleA = createdA.json().path("id").asLong();
    long scheduleB = createdB.json().path("id").asLong();
    assertThat(scheduleA).isPositive();
    assertThat(scheduleB).isPositive();

    assertThat(ids(request("GET", "/scan-schedules", aliceToken, null)))
        .containsExactly(scheduleA);
    assertThat(ids(request("GET", "/scan-schedules", bobToken, null)))
        .containsExactly(scheduleB);
    assertThat(ids(request("GET", "/scan-schedules", adminToken, null)))
        .containsExactlyInAnyOrder(scheduleA, scheduleB);
    assertThat(request("GET", "/scan-schedules/" + scheduleA, aliceToken, null).status())
        .isEqualTo(200);
    assertThat(request("GET", "/scan-schedules/" + scheduleB, bobToken, null).status())
        .isEqualTo(200);

    Response aliceForeign = request("GET", "/scan-schedules/" + scheduleB, aliceToken, null);
    Response bobForeign = request("GET", "/scan-schedules/" + scheduleA, bobToken, null);
    assertThat(aliceForeign.status()).isIn(400, 403);
    assertThat(bobForeign.status()).isIn(400, 403);
    assertThat(aliceForeign.json().path("message").asText()).contains("无权访问");
    assertThat(bobForeign.json().path("message").asText()).contains("无权访问");
    assertThat(request("GET", "/scan-schedules/" + scheduleA, null, null).status())
        .isEqualTo(401);

    // Ownership grants read access, not permission to change global scan schedules.
    for (String userToken : new String[] {aliceToken, bobToken}) {
      assertThat(request("POST", "/scan-schedules", userToken, planA).status()).isEqualTo(403);
      for (long id : new long[] {scheduleA, scheduleB}) {
        assertThat(request("POST", "/scan-schedules/" + id + "/enable", userToken, null).status())
            .isEqualTo(403);
        assertThat(request("POST", "/scan-schedules/" + id + "/disable", userToken, null).status())
            .isEqualTo(403);
        assertThat(request("DELETE", "/scan-schedules/" + id, userToken, null).status())
            .isEqualTo(403);
      }
    }
    Response unchangedA = request("GET", "/scan-schedules/" + scheduleA, adminToken, null);
    Response unchangedB = request("GET", "/scan-schedules/" + scheduleB, adminToken, null);
    assertThat(unchangedA.status()).isEqualTo(200);
    assertThat(unchangedB.status()).isEqualTo(200);
    assertThat(unchangedA.json().path("enabled").asBoolean()).isFalse();
    assertThat(unchangedB.json().path("enabled").asBoolean()).isFalse();
    assertThat(ids(request("GET", "/scan-schedules", adminToken, null))).hasSize(2);

    Response enabled = request("POST", "/scan-schedules/" + scheduleA + "/enable", adminToken, null);
    assertThat(enabled.status()).isEqualTo(200);
    assertThat(enabled.json().path("enabled").asBoolean()).isTrue();
    assertThat(enabled.json().path("nextRunAt").asText()).isNotBlank();
    Response disabled = request("POST", "/scan-schedules/" + scheduleA + "/disable", adminToken, null);
    assertThat(disabled.status()).isEqualTo(200);
    assertThat(disabled.json().path("enabled").asBoolean()).isFalse();
    assertThat(disabled.json().path("nextRunAt").isNull()).isTrue();
    assertThat(request("DELETE", "/scan-schedules/" + scheduleA, adminToken, null).status())
        .isBetween(200, 299);
    assertThat(request("DELETE", "/scan-schedules/" + scheduleB, adminToken, null).status())
        .isBetween(200, 299);
    assertThat(ids(request("GET", "/scan-schedules", adminToken, null))).isEmpty();
    System.out.println(
        "R366_HTTP_E2E: real admin/USER logins; owner lists/details=200; foreign reads="
            + aliceForeign.status() + "/" + bobForeign.status()
            + "; anonymous=401; 14 USER mutation requests=403; denied operations unchanged;"
            + " administrator enable/disable/delete=2xx; plans after cleanup=0; PASS");
  }

  private void seedAccount(String name, String role, String password) {
    User user = new User();
    user.setUsername(name);
    user.setRole(role);
    user.setPasswordHash(encoder.encode(password));
    users.saveAndFlush(user);
  }

  private String login(String name, String password, String role) throws Exception {
    Response response = request("POST", "/auth/login", null, Map.of("username", name, "password", password));
    assertThat(response.status()).as("real login for %s", role).isEqualTo(200);
    assertThat(response.json().path("user").path("role").asText()).isEqualTo(role);
    String token = response.json().path("token").asText();
    assertThat(token).isNotBlank();
    assertThat(request("GET", "/auth/me", token, null).json().path("role").asText())
        .isEqualTo(role);
    return token;
  }

  private long createProject(String token, String owner, String name) throws Exception {
    Instant now = Instant.now();
    Response response =
        request("POST", "/projects", token,
            Map.of("name", "R366 HTTP permission " + name, "description", "isolated HTTP fixture",
                "owner", owner, "authorizationStatement", "R366 fixed-target authorization",
                "authorizationValidFrom", now.minusSeconds(3600).toString(),
                "authorizationExpiresAt", now.plusSeconds(86400).toString()));
    assertThat(response.status()).isEqualTo(201);
    long id = response.json().path("id").asLong();
    assertThat(request("POST", "/projects/" + id + "/status", token, Map.of("status", "ACTIVE")).status())
        .isEqualTo(200);
    return id;
  }

  private long createTarget(String token, long projectId, String marker) throws Exception {
    Response response =
        request("POST", "/targets", token,
            Map.of("projectId", projectId, "name", "R366 target " + marker,
                "targetValue", "http://192.168.222.157/?r366=" + marker, "targetType", "URL",
                "authorizationNote", "R366 disabled schedule permission test", "allowedPorts", "80",
                "enabled", true));
    assertThat(response.status()).isEqualTo(201);
    return response.json().path("id").asLong();
  }

  private Map<String, Object> scheduleRequest(long projectId, long targetId) {
    return Map.of("projectId", projectId, "targetId", targetId, "toolCode", "http_headers",
        "parameters", Map.of(), "intervalSeconds", 3600, "enabled", false);
  }

  private Set<Long> ids(Response response) {
    assertThat(response.status()).isEqualTo(200);
    assertThat(response.json().isArray()).isTrue();
    Set<Long> ids = new HashSet<>();
    response.json().forEach(item -> ids.add(item.path("id").asLong()));
    return ids;
  }

  private Response request(String method, String endpoint, String token, Object payload) throws Exception {
    HttpRequest.Builder builder =
        HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + "/api" + endpoint))
            .timeout(Duration.ofSeconds(30)).header("Content-Type", "application/json");
    if (token != null) builder.header("Authorization", "Bearer " + token);
    builder.method(method, payload == null ? HttpRequest.BodyPublishers.noBody()
        : HttpRequest.BodyPublishers.ofString(mapper.writeValueAsString(payload)));
    HttpResponse<String> response = client.send(builder.build(), HttpResponse.BodyHandlers.ofString());
    JsonNode json;
    try { json = mapper.readTree(response.body()); }
    catch (Exception ignored) { json = mapper.createObjectNode(); }
    if (json == null) json = mapper.createObjectNode();
    return new Response(response.statusCode(), json);
  }

  private record Response(int status, JsonNode json) {}
}
