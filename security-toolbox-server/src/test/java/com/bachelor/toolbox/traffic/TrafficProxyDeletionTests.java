package com.bachelor.toolbox.traffic;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.bachelor.toolbox.audit.AuditLogRepository;
import com.bachelor.toolbox.auth.User;
import com.bachelor.toolbox.auth.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest(
    properties = {
      "spring.datasource.url=jdbc:h2:mem:traffic-delete-test;MODE=PostgreSQL;DB_CLOSE_DELAY=-1",
      "spring.jpa.hibernate.ddl-auto=create-drop",
      "toolbox.ai.api-key=",
      "toolbox.auth.admin-password=test-admin-password-7bbbe095d8724fcb",
      "toolbox.auth.jwt-secret=test-jwt-secret-cdc24d415ad843aa9ef313028ae9be30",
      "toolbox.traffic.mitm-ca-password=test-mitm-ca-password-1d6ad9b95b76490e",
      "toolbox.traffic.mitm-enabled=false"
    })
@AutoConfigureMockMvc
class TrafficProxyDeletionTests {
  @Autowired private MockMvc mockMvc;
  @Autowired private TrafficSessionRepository sessions;
  @Autowired private TrafficPacketRepository packets;
  @Autowired private TrafficSuggestionRepository suggestions;
  @Autowired private AuditLogRepository audits;
  @Autowired private UserRepository users;
  @Autowired private PasswordEncoder passwordEncoder;

  @BeforeEach
  void clearTrafficData() {
    suggestions.deleteAllInBatch();
    packets.deleteAllInBatch();
    sessions.deleteAllInBatch();
    audits.deleteAllInBatch();
  }

  @Test
  void deletesPacketSuggestionAndRepairsSessionCount() throws Exception {
    TrafficSession session = createSession(1);
    TrafficPacket packet = createPacket(session.getId(), "/single-delete");
    TrafficSuggestion suggestion = createSuggestion(packet.getId());

    mockMvc
        .perform(
            delete("/api/traffic/sessions/" + packet.getId())
                .header(
                    "Authorization",
                    "Bearer " + login("admin", "test-admin-password-7bbbe095d8724fcb")))
        .andExpect(status().isNoContent());

    assertFalse(packets.existsById(packet.getId()));
    assertFalse(suggestions.existsById(suggestion.getId()));
    assertEquals(0, sessions.findById(session.getId()).orElseThrow().getPacketCount());
    assertTrue(
        audits.findTop100ByOrderByCreatedAtDesc().stream()
            .anyMatch(
                item ->
                    "DELETE_TRAFFIC_PACKET".equals(item.getAction())
                        && packet.getId().toString().equals(item.getResourceId())));
  }

  @Test
  void clearsPacketsSuggestionsAndAllStoredSessionCounts() throws Exception {
    TrafficSession first = createSession(1);
    TrafficSession second = createSession(1);
    TrafficPacket firstPacket = createPacket(first.getId(), "/first");
    createPacket(second.getId(), "/second");
    createSuggestion(firstPacket.getId());

    mockMvc
        .perform(
            delete("/api/traffic/sessions")
                .header(
                    "Authorization",
                    "Bearer " + login("admin", "test-admin-password-7bbbe095d8724fcb")))
        .andExpect(status().isNoContent());

    assertEquals(0, packets.count());
    assertEquals(0, suggestions.count());
    assertTrue(sessions.findAll().stream().allMatch(item -> item.getPacketCount() == 0));
    assertTrue(
        audits.findTop100ByOrderByCreatedAtDesc().stream()
            .anyMatch(
                item ->
                    "CLEAR_TRAFFIC_PACKETS".equals(item.getAction())
                        && "deletedCount=2,retainedCount=0".equals(item.getDetail())));
  }

  @Test
  void clearKeepsMarkedPacketsAndTheirSuggestions() throws Exception {
    TrafficSession session = createSession(2);
    TrafficPacket marked = createPacket(session.getId(), "/marked");
    marked.setMarked(true);
    packets.save(marked);
    TrafficSuggestion markedSuggestion = createSuggestion(marked.getId());
    TrafficPacket removable = createPacket(session.getId(), "/removable");
    TrafficSuggestion removableSuggestion = createSuggestion(removable.getId());

    mockMvc
        .perform(
            delete("/api/traffic/sessions")
                .header(
                    "Authorization",
                    "Bearer " + login("admin", "test-admin-password-7bbbe095d8724fcb")))
        .andExpect(status().isNoContent());

    assertTrue(packets.existsById(marked.getId()));
    assertTrue(suggestions.existsById(markedSuggestion.getId()));
    assertFalse(packets.existsById(removable.getId()));
    assertFalse(suggestions.existsById(removableSuggestion.getId()));
    assertEquals(1, sessions.findById(session.getId()).orElseThrow().getPacketCount());
  }

  @Test
  void clearsPacketsAndRecountsSessionsAcrossMultipleBatches() throws Exception {
    List<TrafficSession> storedSessions = new ArrayList<>();
    TrafficPacket firstRemovable = null;
    TrafficPacket lastRemovable = null;
    for (int index = 0; index < 205; index++) {
      TrafficSession session = createSession(99);
      storedSessions.add(session);
      TrafficPacket packet = createPacket(session.getId(), "/batch-" + index);
      if (index == 0) {
        firstRemovable = packet;
      }
      lastRemovable = packet;
    }
    createSuggestion(firstRemovable.getId());
    createSuggestion(lastRemovable.getId());

    TrafficSession retainedSession = storedSessions.get(storedSessions.size() - 1);
    TrafficPacket retained = createPacket(retainedSession.getId(), "/retained");
    retained.setMarked(true);
    packets.save(retained);
    TrafficSuggestion retainedSuggestion = createSuggestion(retained.getId());

    mockMvc
        .perform(
            delete("/api/traffic/sessions")
                .header(
                    "Authorization",
                    "Bearer " + login("admin", "test-admin-password-7bbbe095d8724fcb")))
        .andExpect(status().isNoContent());

    assertEquals(1, packets.count());
    assertTrue(packets.existsById(retained.getId()));
    assertEquals(1, suggestions.count());
    assertTrue(suggestions.existsById(retainedSuggestion.getId()));
    for (TrafficSession session : sessions.findAll()) {
      long expected = session.getId().equals(retainedSession.getId()) ? 1 : 0;
      assertEquals(expected, session.getPacketCount());
    }
    assertTrue(
        audits.findTop100ByOrderByCreatedAtDesc().stream()
            .anyMatch(
                item ->
                    "CLEAR_TRAFFIC_PACKETS".equals(item.getAction())
                        && "deletedCount=205,retainedCount=1".equals(item.getDetail())));
  }

  @Test
  void marksAndUnmarksPacket() throws Exception {
    TrafficSession session = createSession(1);
    TrafficPacket packet = createPacket(session.getId(), "/mark-toggle");
    String token = login("admin", "test-admin-password-7bbbe095d8724fcb");

    mockMvc
        .perform(
            put("/api/traffic/sessions/" + packet.getId() + "/marked")
                .header("Authorization", "Bearer " + token)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"marked\":true}"))
        .andExpect(status().isOk());
    assertTrue(packets.findById(packet.getId()).orElseThrow().isMarked());

    mockMvc
        .perform(
            put("/api/traffic/sessions/" + packet.getId() + "/marked")
                .header("Authorization", "Bearer " + token)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"marked\":false}"))
        .andExpect(status().isOk());
    assertFalse(packets.findById(packet.getId()).orElseThrow().isMarked());
  }

  @Test
  void rejectsTrafficDeletionByNonAdminUser() throws Exception {
    TrafficSession session = createSession(1);
    TrafficPacket packet = createPacket(session.getId(), "/forbidden");
    String username = "traffic-user-" + UUID.randomUUID();
    User user = new User();
    user.setUsername(username);
    user.setPasswordHash(passwordEncoder.encode("user-password"));
    user.setRole("USER");
    users.save(user);

    mockMvc
        .perform(
            delete("/api/traffic/sessions/" + packet.getId())
                .header("Authorization", "Bearer " + login(username, "user-password")))
        .andExpect(status().isForbidden());

    assertTrue(packets.existsById(packet.getId()));
  }

  private String login(String username, String password) throws Exception {
    String response =
        mockMvc
            .perform(
                post("/api/auth/login")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(
                        new ObjectMapper()
                            .writeValueAsString(
                                java.util.Map.of(
                                    "username", username,
                                    "password", password))))
            .andExpect(status().isOk())
            .andReturn()
            .getResponse()
            .getContentAsString();
    return new ObjectMapper().readTree(response).path("token").asText();
  }

  private TrafficSession createSession(long packetCount) {
    TrafficSession session = new TrafficSession();
    session.setTargetId(0L);
    session.setName("删除测试会话");
    session.setStatus("STOPPED");
    session.setListenPort(19080);
    session.setHandlingMode("ASK");
    session.setPacketCount(packetCount);
    return sessions.save(session);
  }

  private TrafficPacket createPacket(Long sessionId, String path) {
    TrafficPacket packet = new TrafficPacket();
    packet.setSessionId(sessionId);
    packet.setTargetId(0L);
    packet.setProtocol("HTTP");
    packet.setMethod("GET");
    packet.setScheme("http");
    packet.setHost("127.0.0.1");
    packet.setPort(8080);
    packet.setPath(path);
    packet.setRequestBytes(0);
    packet.setResponseBytes(0);
    return packets.save(packet);
  }

  private TrafficSuggestion createSuggestion(Long packetId) {
    TrafficSuggestion suggestion = new TrafficSuggestion();
    suggestion.setPacketId(packetId);
    suggestion.setTargetId(0L);
    suggestion.setTitle("删除测试建议");
    suggestion.setConfidence(0.8);
    suggestion.setActionType("PASSIVE_CHECK");
    return suggestions.save(suggestion);
  }
}
