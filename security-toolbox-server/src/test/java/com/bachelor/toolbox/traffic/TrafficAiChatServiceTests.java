package com.bachelor.toolbox.traffic;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.ai.AiModelClient;
import com.bachelor.toolbox.audit.AuditService;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class TrafficAiChatServiceTests {
  private final TrafficPacketRepository packets = mock(TrafficPacketRepository.class);
  private final AiModelClient model = mock(AiModelClient.class);
  private final AuditService audit = mock(AuditService.class);
  private final TrafficAiChatService service = new TrafficAiChatService(packets, model, audit);

  @Test
  void sendsRawPacketAndConversationHistoryToTheModel() throws Exception {
    TrafficPacket packet = packet();
    when(packets.findById(7L)).thenReturn(Optional.of(packet));
    when(model.enabled()).thenReturn(true);
    when(model.model()).thenReturn("test-model");
    when(model.complete(contains("流量分析助手"), contains("Authorization: Bearer raw-token")))
        .thenReturn("这是分析结果");

    TrafficAiChatService.ChatResponse response =
        service.chat(
            7L,
            new TrafficAiChatService.ChatRequest(
                "这个请求有什么问题？", List.of(new TrafficAiChatService.ChatMessage("USER", "先看认证信息"))));

    assertEquals("这是分析结果", response.answer());
    assertEquals("openai-compatible", response.provider());
    verify(model).complete(contains("流量分析助手"), contains("先看认证信息"));
  }

  @Test
  void returnsPacketSummaryWhenModelIsDisabled() {
    when(packets.findById(7L)).thenReturn(Optional.of(packet()));
    when(model.enabled()).thenReturn(false);

    TrafficAiChatService.ChatResponse response =
        service.chat(7L, new TrafficAiChatService.ChatRequest("总结", List.of()));

    assertTrue(response.answer().contains("POST /login"));
    assertEquals("local-summary", response.provider());
  }

  @Test
  void hidesModelFailureDetailsFromTheResponse() throws Exception {
    when(packets.findById(7L)).thenReturn(Optional.of(packet()));
    when(model.enabled()).thenReturn(true);
    when(model.complete(contains("流量分析助手"), contains("当前问题：总结")))
        .thenThrow(new IllegalStateException("secret-provider-detail"));

    TrafficAiChatService.ChatResponse response =
        service.chat(7L, new TrafficAiChatService.ChatRequest("总结", List.of()));

    assertTrue(response.answer().contains("AI 模型暂时无法返回回答"));
    assertFalse(response.answer().contains("secret-provider-detail"));
    assertEquals("local-summary", response.provider());
  }

  private TrafficPacket packet() {
    TrafficPacket packet = new TrafficPacket();
    packet.setId(7L);
    packet.setProtocol("HTTPS");
    packet.setMethod("POST");
    packet.setScheme("https");
    packet.setHost("example.com");
    packet.setPort(443);
    packet.setPath("/login");
    packet.setStatusCode(401);
    packet.setContentType("application/json");
    packet.setRequestHeaders("Authorization: Bearer raw-token");
    packet.setRequestBody("{\"username\":\"admin\"}");
    packet.setResponseHeaders("Content-Type: application/json");
    packet.setResponseBody("{\"error\":\"unauthorized\"}");
    return packet;
  }
}
