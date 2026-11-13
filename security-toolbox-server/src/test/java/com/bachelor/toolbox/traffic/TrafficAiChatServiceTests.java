package com.bachelor.toolbox.traffic;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.ai.AiModelClient;
import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.common.ApiException;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class TrafficAiChatServiceTests {
  private final TrafficPacketRepository packets = mock(TrafficPacketRepository.class);
  private final AiModelClient model = mock(AiModelClient.class);
  private final AuditService audit = mock(AuditService.class);
  private final com.bachelor.toolbox.project.ProjectTargetRepository projectTargets =
      mock(com.bachelor.toolbox.project.ProjectTargetRepository.class);
  private final com.bachelor.toolbox.project.ProjectAuthorizationService authorization =
      mock(com.bachelor.toolbox.project.ProjectAuthorizationService.class);
  private final TrafficAiChatService service =
      new TrafficAiChatService(packets, model, audit, projectTargets, authorization);

  private void grantAccess(Long targetId, Long projectId) {
    var link = new com.bachelor.toolbox.project.ProjectTarget();
    link.setProjectId(projectId);
    link.setTargetId(targetId);
    when(projectTargets.findByTargetId(targetId)).thenReturn(java.util.List.of(link));
    when(authorization.requireAccess(projectId))
        .thenReturn(new com.bachelor.toolbox.project.AssessmentProject());
  }

  @Test
  void sendsRedactedPacketAndConversationHistoryForAuthorizedTarget() throws Exception {
    TrafficPacket packet = packet();
    packet.setTargetId(11L);
    grantAccess(11L, 5L);
    when(packets.findById(7L)).thenReturn(Optional.of(packet));
    when(model.enabled()).thenReturn(true);
    when(model.model()).thenReturn("test-model");
    when(model.complete(contains("流量分析助手"), contains("[REDACTED]")))
        .thenReturn("这是分析结果");

    TrafficAiChatService.ChatResponse response =
        service.chat(
            7L,
            new TrafficAiChatService.ChatRequest(
                "这个请求有什么问题？", List.of(new TrafficAiChatService.ChatMessage("USER", "先看认证信息"))));

    assertEquals("这是分析结果", response.answer());
    assertEquals("openai-compatible", response.provider());
    verify(model).complete(contains("流量分析助手"), contains("先看认证信息"));
    var prompt = org.mockito.ArgumentCaptor.forClass(String.class);
    verify(model).complete(contains("流量分析助手"), prompt.capture());
    assertFalse(prompt.getValue().contains("raw-token"));
  }

  @Test
  void rejectsChatWhenUserHasNoAccessToPacketProject() {
    // Round 34：IDOR —— 目标不属于任何当前用户可访问项目时拒绝，模型不应被调用。
    TrafficPacket packet = packet();
    packet.setTargetId(11L);
    when(packets.findById(7L)).thenReturn(Optional.of(packet));
    when(projectTargets.findByTargetId(11L)).thenReturn(java.util.List.of());
    assertThatThrownBy(() -> service.chat(7L, new TrafficAiChatService.ChatRequest("总结", List.of())))
        .isInstanceOf(ApiException.class).hasMessageContaining("无权访问");
  }

  @Test
  void rejectsTheQuestionWhenModelIsDisabled() {
    TrafficPacket p = packet();
    p.setTargetId(11L);
    grantAccess(11L, 5L);
    when(packets.findById(7L)).thenReturn(Optional.of(p));
    when(model.enabled()).thenReturn(false);

    assertThatThrownBy(() -> service.chat(7L, new TrafficAiChatService.ChatRequest("总结", List.of())))
        .isInstanceOf(ApiException.class).hasMessageContaining("尚未配置或启用 AI 模型");
  }

  @Test
  void hidesModelFailureDetailsFromTheResponse() throws Exception {
    TrafficPacket p = packet();
    p.setTargetId(11L);
    grantAccess(11L, 5L);
    when(packets.findById(7L)).thenReturn(Optional.of(p));
    when(model.enabled()).thenReturn(true);
    when(model.complete(contains("流量分析助手"), contains("当前问题：总结")))
        .thenThrow(new IllegalStateException("secret-provider-detail"));

    assertThatThrownBy(() -> service.chat(7L, new TrafficAiChatService.ChatRequest("总结", List.of())))
        .isInstanceOf(ApiException.class).hasMessageContaining("AI 模型暂时无法返回回答")
        .hasMessageNotContaining("secret-provider-detail");
    verify(audit).record("AI_CHAT_TRAFFIC", "TRAFFIC_PACKET", 7L, "model response unavailable", "FAILED");
  }

  @Test
  void rejectsAnEmptyModelAnswer() throws Exception {
    TrafficPacket p = packet();
    p.setTargetId(11L);
    grantAccess(11L, 5L);
    when(packets.findById(7L)).thenReturn(Optional.of(p));
    when(model.enabled()).thenReturn(true);
    when(model.complete(contains("流量分析助手"), contains("当前问题：总结"))).thenReturn(" ");
    assertThatThrownBy(() -> service.chat(7L, new TrafficAiChatService.ChatRequest("总结", List.of())))
        .isInstanceOf(ApiException.class).hasMessageContaining("AI 模型暂时无法返回回答");
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
