package com.bachelor.toolbox.traffic;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.ai.AiModelClient;
import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.project.ProjectTarget;
import com.bachelor.toolbox.project.ProjectTargetRepository;
import com.bachelor.toolbox.task.CreateTaskRequest;
import com.bachelor.toolbox.task.SecurityTask;
import com.bachelor.toolbox.task.TaskService;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.ArgumentCaptor;

class TrafficAnalysisServiceTests {
  private static final long SUGGESTION_ID = 11L;
  private static final long PACKET_ID = 41L;
  private static final long TARGET_ID = 73L;

  private final TrafficPacketRepository packets = mock(TrafficPacketRepository.class);
  private final TrafficSuggestionRepository suggestions = mock(TrafficSuggestionRepository.class);
  private final TaskService tasks = mock(TaskService.class);
  private final AuditService audit = mock(AuditService.class);
  private final AiModelClient modelClient = mock(AiModelClient.class);
  private final ProjectTargetRepository projectTargets = mock(ProjectTargetRepository.class);
  private final TrafficAnalysisService service =
      new TrafficAnalysisService(packets, suggestions, tasks, audit, modelClient, projectTargets);

  @ParameterizedTest
  @CsvSource({"EXECUTED,DONE", "IGNORED,IGNORED", "PENDING,PENDING"})
  void reanalysisCallsTheModelAgainAndPreservesItsDecisionState(String suggestionStatus, String packetStatus) throws Exception {
    TrafficSuggestion suggestion = executableSuggestion();
    suggestion.setStatus(suggestionStatus);
    suggestion.setTaskId(101L);
    suggestion.setDecidedAt(java.time.Instant.parse("2026-10-01T00:00:00Z"));
    TrafficPacket packet = analysisPacket();
    packet.setAiStatus(packetStatus);
    when(packets.findById(PACKET_ID)).thenReturn(Optional.of(packet));
    when(suggestions.findByPacketId(PACKET_ID)).thenReturn(Optional.of(suggestion));
    when(suggestions.save(suggestion)).thenReturn(suggestion);
    when(modelClient.enabled()).thenReturn(true);
    when(modelClient.complete(any(), any())).thenReturn("第一次模型分析", "第二次模型分析");

    service.analyze(PACKET_ID, "SUGGEST_ONLY");
    TrafficAnalysisService.AnalysisResponse response = service.analyze(PACKET_ID, "SUGGEST_ONLY");

    assertThat(response.summary()).isEqualTo("第二次模型分析");
    assertThat(response.suggestionId()).isEqualTo(SUGGESTION_ID);
    assertThat(response.taskId()).isEqualTo(101L);
    assertThat(response.status()).isEqualTo(suggestionStatus);
    assertThat(suggestion.getDecidedAt()).isEqualTo(java.time.Instant.parse("2026-10-01T00:00:00Z"));
    assertThat(packet.getAiStatus()).isEqualTo(packetStatus);
    verify(packets, times(2)).save(packet);
    verify(suggestions, times(2)).save(suggestion);
    verify(modelClient, times(2)).complete(any(), any());
    verify(tasks, never()).create(any());
  }

  @Test
  void enhancesNewAnalysisWithAiWhileRetainingTheControlledAction() throws Exception {
    TrafficPacket packet = analysisPacket();
    packet.setRequestHeaders("Authorization: Bearer raw-token");
    prepareNewAnalysis(packet);
    when(modelClient.enabled()).thenReturn(true);
    when(modelClient.complete(any(), any())).thenReturn("模型引用 401 响应建议检查认证配置。");

    TrafficAnalysisService.AnalysisResponse response = service.analyze(PACKET_ID, "SUGGEST_ONLY");

    ArgumentCaptor<String> prompt = ArgumentCaptor.forClass(String.class);
    verify(modelClient).complete(any(), prompt.capture());
    assertThat(prompt.getValue()).contains("method=GET", "url=https://127.0.0.1:8443/login", "status=401",
        "本地规则参考模板", "Content-Security-Policy", "[REDACTED]").doesNotContain("raw-token");
    ArgumentCaptor<TrafficSuggestion> saved = ArgumentCaptor.forClass(TrafficSuggestion.class);
    verify(suggestions).save(saved.capture());
    assertThat(saved.getValue().getSource()).isEqualTo("AI");
    assertThat(saved.getValue().getToolCode()).isEqualTo("http_headers");
    assertThat(saved.getValue().isRequiresConfirmation()).isTrue();
    assertThat(response.summary()).isEqualTo("模型引用 401 响应建议检查认证配置。");
    assertThat(response.status()).isEqualTo("PENDING");
    verify(tasks, never()).create(any(CreateTaskRequest.class));
  }

  @Test
  void modelFailureDoesNotSaveLocalRulesAsAnAiAnalysis() throws Exception {
    prepareNewAnalysis(analysisPacket());
    when(modelClient.enabled()).thenReturn(true);
    when(modelClient.complete(any(), any())).thenThrow(new IllegalStateException("provider-detail"));

    assertThatThrownBy(() -> service.analyze(PACKET_ID, "SUGGEST_ONLY"))
        .isInstanceOf(ApiException.class).hasMessageContaining("未能完成流量分析")
        .hasMessageNotContaining("provider-detail");
    verify(suggestions, never()).save(any(TrafficSuggestion.class));
    verify(packets, never()).save(any(TrafficPacket.class));
    verify(tasks, never()).create(any(CreateTaskRequest.class));
  }

  @Test
  void disabledModelDoesNotReportASuccessfulAnalysis() throws Exception {
    prepareNewAnalysis(analysisPacket());
    when(modelClient.enabled()).thenReturn(false);
    assertThatThrownBy(() -> service.analyze(PACKET_ID, "SUGGEST_ONLY"))
        .isInstanceOf(ApiException.class).hasMessageContaining("尚未配置或启用 AI 模型");
    verify(modelClient, never()).complete(any(), any());
    verify(suggestions, never()).save(any());
    verify(packets, never()).save(any());
  }

  @Test
  void emptyModelResponseDoesNotSaveAnAnalysis() throws Exception {
    prepareNewAnalysis(analysisPacket());
    when(modelClient.enabled()).thenReturn(true);
    when(modelClient.complete(any(), any())).thenReturn(" ");
    assertThatThrownBy(() -> service.analyze(PACKET_ID, "SUGGEST_ONLY"))
        .isInstanceOf(ApiException.class).hasMessageContaining("未能完成流量分析");
    verify(suggestions, never()).save(any());
    verify(packets, never()).save(any());
  }

  private void prepareNewAnalysis(TrafficPacket packet) {
    when(packets.findById(PACKET_ID)).thenReturn(Optional.of(packet));
    when(suggestions.findByPacketId(PACKET_ID)).thenReturn(Optional.empty());
    when(suggestions.save(any(TrafficSuggestion.class))).thenAnswer(invocation -> invocation.getArgument(0));
  }

  private TrafficPacket analysisPacket() {
    TrafficPacket packet = new TrafficPacket();
    packet.setId(PACKET_ID);
    packet.setTargetId(TARGET_ID);
    packet.setProtocol("HTTPS");
    packet.setScheme("https");
    packet.setHost("127.0.0.1");
    packet.setPort(8443);
    packet.setPath("/login");
    packet.setMethod("GET");
    packet.setStatusCode(401);
    return packet;
  }

  @Test
  void createsTaskWithTheOnlyProjectBoundToTheTrafficTarget() throws Exception {
    TrafficSuggestion suggestion = executableSuggestion();
    TrafficPacket packet = new TrafficPacket();
    SecurityTask createdTask = new SecurityTask();
    createdTask.setId(101L);
    when(suggestions.findById(SUGGESTION_ID)).thenReturn(Optional.of(suggestion));
    when(projectTargets.findByTargetId(TARGET_ID))
        .thenReturn(List.of(new ProjectTarget(29L, TARGET_ID)));
    when(tasks.create(any(CreateTaskRequest.class))).thenReturn(createdTask);
    when(packets.findById(PACKET_ID)).thenReturn(Optional.of(packet));

    TrafficAnalysisService.AnalysisResponse response = service.execute(SUGGESTION_ID);

    ArgumentCaptor<CreateTaskRequest> request = ArgumentCaptor.forClass(CreateTaskRequest.class);
    verify(tasks).create(request.capture());
    assertThat(request.getValue().projectId()).isEqualTo(29L);
    assertThat(request.getValue().targetId()).isEqualTo(TARGET_ID);
    assertThat(request.getValue().toolCode()).isEqualTo("http_headers");
    assertThat(request.getValue().parameters()).isEmpty();
    assertThat(response.status()).isEqualTo("EXECUTED");
    assertThat(response.taskId()).isEqualTo(101L);
    assertThat(suggestion.getTaskId()).isEqualTo(101L);
    assertThat(packet.getAiStatus()).isEqualTo("DONE");
    verify(suggestions).save(suggestion);
    verify(packets).save(packet);
  }

  @Test
  void rejectsTaskCreationWhenTrafficTargetIsNotBoundToAProject() throws Exception {
    TrafficSuggestion suggestion = executableSuggestion();
    when(suggestions.findById(SUGGESTION_ID)).thenReturn(Optional.of(suggestion));
    when(projectTargets.findByTargetId(TARGET_ID)).thenReturn(List.of());

    assertThatThrownBy(() -> service.execute(SUGGESTION_ID))
        .hasMessageContaining("未绑定到任何评估项目");

    verify(tasks, never()).create(any(CreateTaskRequest.class));
    verify(suggestions, never()).save(any(TrafficSuggestion.class));
    verify(packets, never()).save(any(TrafficPacket.class));
  }

  @Test
  void rejectsAmbiguousTaskCreationWhenTrafficTargetIsBoundToMultipleProjects() throws Exception {
    TrafficSuggestion suggestion = executableSuggestion();
    when(suggestions.findById(SUGGESTION_ID)).thenReturn(Optional.of(suggestion));
    when(projectTargets.findByTargetId(TARGET_ID))
        .thenReturn(
            List.of(new ProjectTarget(29L, TARGET_ID), new ProjectTarget(31L, TARGET_ID)));

    assertThatThrownBy(() -> service.execute(SUGGESTION_ID))
        .hasMessageContaining("绑定了多个评估项目")
        .hasMessageContaining("项目页面手动创建");

    verify(tasks, never()).create(any(CreateTaskRequest.class));
    verify(suggestions, never()).save(any(TrafficSuggestion.class));
    verify(packets, never()).save(any(TrafficPacket.class));
  }

  private TrafficSuggestion executableSuggestion() {
    TrafficSuggestion suggestion = new TrafficSuggestion();
    suggestion.setId(SUGGESTION_ID);
    suggestion.setPacketId(PACKET_ID);
    suggestion.setTargetId(TARGET_ID);
    suggestion.setSummary("建议检查 Web 安全基线");
    suggestion.setSeverity("MEDIUM");
    suggestion.setReason("响应缺少安全头");
    suggestion.setTitle("检查 Web 安全基线");
    suggestion.setToolCode("http_headers");
    suggestion.setStatus("PENDING");
    return suggestion;
  }
}
