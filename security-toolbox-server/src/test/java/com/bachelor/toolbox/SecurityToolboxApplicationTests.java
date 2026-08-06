package com.bachelor.toolbox;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.asyncDispatch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.request;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.net.ProxySelector;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest(
    properties = {
      "spring.datasource.url=jdbc:h2:mem:toolbox-test;MODE=PostgreSQL;DB_CLOSE_DELAY=-1",
      "spring.jpa.hibernate.ddl-auto=create-drop",
      "toolbox.ai.api-key=",
      "toolbox.auth.admin-password=test-admin-password-7bbbe095d8724fcb",
      "toolbox.auth.jwt-secret=test-jwt-secret-cdc24d415ad843aa9ef313028ae9be30",
      "toolbox.traffic.mitm-ca-password=test-mitm-ca-password-1d6ad9b95b76490e",
      "toolbox.traffic.mitm-enabled=false"
    })
@AutoConfigureMockMvc
class SecurityToolboxApplicationTests {
  @Autowired private MockMvc mockMvc;

  private String login() throws Exception {
    String response =
        mockMvc
            .perform(
                post("/api/auth/login")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(
                        "{\"username\":\"admin\",\"password\":\"test-admin-password-7bbbe095d8724fcb\"}"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.token").isString())
            .andExpect(jsonPath("$.user.username").value("admin"))
            .andReturn()
            .getResponse()
            .getContentAsString();
    return new com.fasterxml.jackson.databind.ObjectMapper()
        .readTree(response)
        .path("token")
        .asText();
  }

  private long createProject(String token, String name) throws Exception {
    java.time.Instant now = java.time.Instant.now();
    String response =
        mockMvc
            .perform(
                post("/api/projects")
                    .header("Authorization", "Bearer " + token)
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(
                        """
{"name":"%s","description":"Integration test project","authorizationStatement":"Automated test authorization","authorizationValidFrom":"%s","authorizationExpiresAt":"%s","owner":"admin"}
"""
                            .formatted(name, now.minusSeconds(60), now.plusSeconds(3600))))
            .andExpect(status().isCreated())
            .andReturn()
            .getResponse()
            .getContentAsString();
    return new com.fasterxml.jackson.databind.ObjectMapper().readTree(response).path("id").asLong();
  }

  private void activateProject(String token, long projectId) throws Exception {
    mockMvc
        .perform(
            post("/api/projects/" + projectId + "/status")
                .header("Authorization", "Bearer " + token)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"status\":\"ACTIVE\"}"))
        .andExpect(status().isOk());
  }

  @Test
  void createsAuthorizedTargetAndFallbackAiPlan() throws Exception {
    String token = login();
    long projectId = createProject(token, "AI fallback project");
    String targetJson =
        """
        {
          "name": "Local test",
          "targetValue": "http://127.0.0.1:8080",
          "targetType": "URL",
          "authorizationNote": "Automated local test authorization",
          "allowedPorts": "8080",
          "enabled": true,
          "projectId": %d
        }
        """
            .formatted(projectId);
    String response =
        mockMvc
            .perform(
                post("/api/targets")
                    .header("Authorization", "Bearer " + token)
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(targetJson))
            .andExpect(status().isCreated())
            .andExpect(jsonPath("$.id").isNumber())
            .andReturn()
            .getResponse()
            .getContentAsString();

    long targetId =
        new com.fasterxml.jackson.databind.ObjectMapper().readTree(response).path("id").asLong();
    activateProject(token, projectId);
    mockMvc
        .perform(
            post("/api/ai/plans")
                .header("Authorization", "Bearer " + token)
                .contentType(MediaType.APPLICATION_JSON)
                .content(
                    "{\"projectId\":"
                        + projectId
                        + ",\"targetId\":"
                        + targetId
                        + ",\"prompt\":\"scan ports and http headers\"}"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.provider").value("local-rule-fallback"))
        .andExpect(jsonPath("$.steps[0].toolCode").exists());

    mockMvc
        .perform(
            post("/api/ai/plans")
                .header("Authorization", "Bearer " + token)
                .contentType(MediaType.APPLICATION_JSON)
                .content(
                    "{\"projectId\":"
                        + projectId
                        + ",\"targetId\":"
                        + targetId
                        + ",\"prompt\":\"use nmap service scan and identify versions\"}"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.steps[0].toolCode").value("nmap_service_scan"))
        .andExpect(jsonPath("$.steps[0].parameters.mode").value("service"));

    mockMvc
        .perform(
            post("/api/ai/dispatches")
                .header("Authorization", "Bearer " + token)
                .contentType(MediaType.APPLICATION_JSON)
                .content(
                    "{\"projectId\":"
                        + projectId
                        + ",\"targetId\":"
                        + targetId
                        + ",\"prompt\":\"check http security headers\"}"))
        .andExpect(status().isAccepted())
        .andExpect(jsonPath("$.targetId").value(targetId))
        .andExpect(jsonPath("$.taskCount").value(1))
        .andExpect(jsonPath("$.taskIds[0]").isNumber())
        .andExpect(jsonPath("$.plan.requiresConfirmation").value(false))
        .andExpect(jsonPath("$.plan.steps[0].toolCode").value("http_headers"));

    mockMvc.perform(get("/api/dashboard/summary")).andExpect(status().isUnauthorized());
    mockMvc
        .perform(get("/api/auth/me").header("Authorization", "Bearer " + token))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.username").value("admin"));
    mockMvc
        .perform(get("/api/dashboard/summary").header("Authorization", "Bearer " + token))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.targets").isNumber());
  }

  @Test
  void exposesLocalDependencyStatusBeforeLogin() throws Exception {
    mockMvc
        .perform(get("/api/system/health"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.status").value("UP"));
    mockMvc
        .perform(get("/api/system/dependencies"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.os").isString())
        .andExpect(jsonPath("$.arch").isString())
        .andExpect(jsonPath("$.dependencies").isArray())
        .andExpect(jsonPath("$.dependencies[?(@.name == 'Java')]").exists())
        .andExpect(jsonPath("$.dependencies[?(@.name == 'Nmap')]").exists());
  }

  @Test
  void keepsAuthenticationDuringAiStreamingAsyncDispatch() throws Exception {
    String token = login();
    long projectId = createProject(token, "AI stream project");
    String targetResponse =
        mockMvc
            .perform(
                post("/api/targets")
                    .header("Authorization", "Bearer " + token)
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(
                        """
{"name":"AI stream target","targetValue":"http://127.0.0.1:18002","targetType":"URL","authorizationNote":"Async stream integration test","allowedPorts":"18002","enabled":true,"projectId":%d}
"""
                            .formatted(projectId)))
            .andExpect(status().isCreated())
            .andReturn()
            .getResponse()
            .getContentAsString();
    long targetId =
        new com.fasterxml.jackson.databind.ObjectMapper()
            .readTree(targetResponse)
            .path("id")
            .asLong();
    activateProject(token, projectId);

    var initial =
        mockMvc
            .perform(
                post("/api/ai/dispatches/stream")
                    .header("Authorization", "Bearer " + token)
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(
                        "{\"projectId\":"
                            + projectId
                            + ",\"targetId\":"
                            + targetId
                            + ",\"prompt\":\"check http headers\"}"))
            .andExpect(request().asyncStarted())
            .andReturn();

    mockMvc
        .perform(asyncDispatch(initial))
        .andExpect(status().isOk())
        .andExpect(content().contentTypeCompatibleWith("application/x-ndjson"))
        .andExpect(content().string(org.hamcrest.Matchers.containsString("\"type\":\"done\"")));
  }

  @Test
  void exposesVulnerabilityCatalogAndStartsSafeActiveScan() throws Exception {
    String token = login();
    long projectId = createProject(token, "Active scan project");
    mockMvc
        .perform(get("/api/vulnerabilities").header("Authorization", "Bearer " + token))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.content[?(@.vulnerabilityCode == 'STB-WEB-001')]").exists());
    mockMvc
        .perform(get("/api/vulnerabilities/rules").header("Authorization", "Bearer " + token))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$[?(@.ruleCode == 'RULE-WEB-HEADERS')]").exists());

    String targetResponse =
        mockMvc
            .perform(
                post("/api/targets")
                    .header("Authorization", "Bearer " + token)
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(
                        """
                        {
                          "name": "Active scan local target",
                          "targetValue": "http://127.0.0.1:18001",
                          "targetType": "URL",
                          "authorizationNote": "Automated active scan test authorization",
                          "allowedPorts": "18001",
                          "enabled": true,
                          "projectId": %d
                        }
                        """
                            .formatted(projectId)))
            .andExpect(status().isCreated())
            .andReturn()
            .getResponse()
            .getContentAsString();
    long targetId =
        new com.fasterxml.jackson.databind.ObjectMapper()
            .readTree(targetResponse)
            .path("id")
            .asLong();
    activateProject(token, projectId);

    mockMvc
        .perform(
            post("/api/active-scans")
                .header("Authorization", "Bearer " + token)
                .contentType(MediaType.APPLICATION_JSON)
                .content(
                    "{\"projectId\":"
                        + projectId
                        + ",\"targetId\":"
                        + targetId
                        + ",\"ruleCodes\":[\"RULE-WEB-HEADERS\"]}"))
        .andExpect(status().isAccepted())
        .andExpect(jsonPath("$.taskCount").value(1))
        .andExpect(jsonPath("$.taskIds[0]").isNumber());
  }

  @Test
  void capturesAuthorizedHttpTrafficAndCreatesSuggestion() throws Exception {
    HttpServer targetServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    targetServer.createContext(
        "/demo",
        exchange -> {
          byte[] body = "proxy-ok".getBytes(java.nio.charset.StandardCharsets.UTF_8);
          exchange.getResponseHeaders().add("Content-Type", "text/plain");
          exchange.sendResponseHeaders(200, body.length);
          exchange.getResponseBody().write(body);
          exchange.close();
        });
    targetServer.start();
    int targetPort = targetServer.getAddress().getPort();
    int proxyPort = findAvailableProxyPort();
    String token = login();
    long projectId = createProject(token, "Traffic proxy project");
    try {
      String targetResponse =
          mockMvc
              .perform(
                  post("/api/targets")
                      .header("Authorization", "Bearer " + token)
                      .contentType(MediaType.APPLICATION_JSON)
                      .content(
                          """
{"name":"Proxy target","targetValue":"http://127.0.0.1:%d","targetType":"URL","authorizationNote":"Local proxy integration test","allowedPorts":"%d","enabled":true,"projectId":%d}
"""
                              .formatted(targetPort, targetPort, projectId)))
              .andExpect(status().isCreated())
              .andReturn()
              .getResponse()
              .getContentAsString();
      long targetId =
          new com.fasterxml.jackson.databind.ObjectMapper()
              .readTree(targetResponse)
              .path("id")
              .asLong();
      activateProject(token, projectId);
      mockMvc
          .perform(
              post("/api/traffic/proxy/start")
                  .header("Authorization", "Bearer " + token)
                  .contentType(MediaType.APPLICATION_JSON)
                  .content(
                      "{\"targetId\":"
                          + targetId
                          + ",\"port\":"
                          + proxyPort
                          + ",\"handlingMode\":\"ASK\"}"))
          .andExpect(status().isOk())
          .andExpect(jsonPath("$.running").value(true));
      mockMvc
          .perform(
              post("/api/traffic/proxy/capture")
                  .header("Authorization", "Bearer " + token)
                  .contentType(MediaType.APPLICATION_JSON)
                  .content("{\"enabled\":true}"))
          .andExpect(status().isOk())
          .andExpect(jsonPath("$.capturing").value(true));

      HttpClient client =
          HttpClient.newBuilder()
              .proxy(ProxySelector.of(new InetSocketAddress("127.0.0.1", proxyPort)))
              .build();
      HttpResponse<String> proxied =
          client.send(
              HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + targetPort + "/demo"))
                  .GET()
                  .build(),
              HttpResponse.BodyHandlers.ofString());
      org.junit.jupiter.api.Assertions.assertEquals("proxy-ok", proxied.body());
      Thread.sleep(200);
      String packets =
          mockMvc
              .perform(get("/api/traffic/sessions").header("Authorization", "Bearer " + token))
              .andExpect(status().isOk())
              .andExpect(jsonPath("$[0].method").value("GET"))
              .andReturn()
              .getResponse()
              .getContentAsString();
      long packetId =
          new com.fasterxml.jackson.databind.ObjectMapper()
              .readTree(packets)
              .get(0)
              .path("id")
              .asLong();
      mockMvc
          .perform(
              post("/api/traffic/sessions/" + packetId + "/analyze")
                  .header("Authorization", "Bearer " + token)
                  .contentType(MediaType.APPLICATION_JSON)
                  .content("{}"))
          .andExpect(status().isOk())
          .andExpect(jsonPath("$.suggestionId").isNumber());
    } finally {
      mockMvc
          .perform(post("/api/traffic/proxy/stop").header("Authorization", "Bearer " + token))
          .andReturn();
      targetServer.stop(0);
    }
  }

  @Test
  void capturesHttpTrafficWithoutSelectingTarget() throws Exception {
    HttpServer targetServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    targetServer.createContext(
        "/open-proxy-demo",
        exchange -> {
          byte[] body = "generic-proxy-ok".getBytes(java.nio.charset.StandardCharsets.UTF_8);
          exchange.getResponseHeaders().add("Content-Type", "text/plain");
          exchange.sendResponseHeaders(200, body.length);
          exchange.getResponseBody().write(body);
          exchange.close();
        });
    targetServer.start();
    int targetPort = targetServer.getAddress().getPort();
    int proxyPort = findAvailableProxyPort();
    String token = login();
    try {
      mockMvc
          .perform(
              post("/api/traffic/proxy/start")
                  .header("Authorization", "Bearer " + token)
                  .contentType(MediaType.APPLICATION_JSON)
                  .content("{\"port\":" + proxyPort + ",\"handlingMode\":\"ASK\"}"))
          .andExpect(status().isOk())
          .andExpect(jsonPath("$.running").value(true))
          .andExpect(jsonPath("$.targetId").doesNotExist());
      mockMvc
          .perform(
              post("/api/traffic/proxy/capture")
                  .header("Authorization", "Bearer " + token)
                  .contentType(MediaType.APPLICATION_JSON)
                  .content("{\"enabled\":true}"))
          .andExpect(status().isOk())
          .andExpect(jsonPath("$.capturing").value(true));

      HttpClient client =
          HttpClient.newBuilder()
              .proxy(ProxySelector.of(new InetSocketAddress("127.0.0.1", proxyPort)))
              .build();
      HttpResponse<String> proxied =
          client.send(
              HttpRequest.newBuilder(
                      URI.create("http://127.0.0.1:" + targetPort + "/open-proxy-demo"))
                  .GET()
                  .build(),
              HttpResponse.BodyHandlers.ofString());
      org.junit.jupiter.api.Assertions.assertEquals("generic-proxy-ok", proxied.body());
      Thread.sleep(200);
      String packets =
          mockMvc
              .perform(get("/api/traffic/sessions").header("Authorization", "Bearer " + token))
              .andExpect(status().isOk())
              .andExpect(jsonPath("$[0].method").value("GET"))
              .andReturn()
              .getResponse()
              .getContentAsString();
      long packetId =
          new com.fasterxml.jackson.databind.ObjectMapper()
              .readTree(packets)
              .get(0)
              .path("id")
              .asLong();
      mockMvc
          .perform(
              post("/api/traffic/sessions/" + packetId + "/analyze")
                  .header("Authorization", "Bearer " + token)
                  .contentType(MediaType.APPLICATION_JSON)
                  .content("{}"))
          .andExpect(status().isOk())
          .andExpect(jsonPath("$.canAutoHandle").value(false));
    } finally {
      mockMvc
          .perform(post("/api/traffic/proxy/stop").header("Authorization", "Bearer " + token))
          .andReturn();
      targetServer.stop(0);
    }
  }

  private int findAvailableProxyPort() throws Exception {
    for (int port = 19080; port <= 19120; port++) {
      try (ServerSocket ignored =
          new ServerSocket(port, 1, java.net.InetAddress.getLoopbackAddress())) {
        return port;
      } catch (java.net.BindException ignored) {
        // Try the next port in the application's allowed local proxy range.
      }
    }
    throw new IllegalStateException("No free local proxy test port in 19080-19120");
  }
}
