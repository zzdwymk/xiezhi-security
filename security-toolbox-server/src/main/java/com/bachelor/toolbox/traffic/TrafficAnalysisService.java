package com.bachelor.toolbox.traffic;

import com.bachelor.toolbox.ai.AiModelClient;
import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.project.ProjectTargetRepository;
import com.bachelor.toolbox.task.CreateTaskRequest;
import com.bachelor.toolbox.task.SecurityTask;
import com.bachelor.toolbox.task.TaskService;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

@Service
public class TrafficAnalysisService {
  private static final Logger LOGGER = LoggerFactory.getLogger(TrafficAnalysisService.class);
  private static final Set<String> ACTION_TOOLS =
      Set.of("http_headers", "tls_config", "nmap_service_scan");

  private final TrafficPacketRepository packets;
  private final TrafficSuggestionRepository suggestions;
  private final TaskService tasks;
  private final AuditService audit;
  private final AiModelClient modelClient;
  private final ProjectTargetRepository projectTargets;

  public TrafficAnalysisService(
      TrafficPacketRepository packets,
      TrafficSuggestionRepository suggestions,
      TaskService tasks,
      AuditService audit,
      AiModelClient modelClient,
      ProjectTargetRepository projectTargets) {
    this.packets = packets;
    this.suggestions = suggestions;
    this.tasks = tasks;
    this.audit = audit;
    this.modelClient = modelClient;
    this.projectTargets = projectTargets;
  }

  public AnalysisResponse analyze(Long packetId, String mode) {
    TrafficPacket packet =
        packets.findById(packetId).orElseThrow(() -> new ApiException("流量记录不存在"));
    TrafficSuggestion suggestion =
        suggestions.findByPacketId(packetId).orElseGet(() -> createSuggestion(packet));
    packet.setAiStatus("PENDING");
    packets.save(packet);
    audit.record("ANALYZE_TRAFFIC", "TRAFFIC_PACKET", packetId, "mode=" + mode, "SUCCESS");
    return response(suggestion);
  }

  public AnalysisResponse execute(Long suggestionId) throws Exception {
    TrafficSuggestion suggestion =
        suggestions.findById(suggestionId).orElseThrow(() -> new ApiException("AI 建议不存在"));
    if (suggestion.getTargetId() == null || suggestion.getTargetId() <= 0) {
      throw new ApiException("通用流量会话未绑定授权目标，不能直接创建检测任务");
    }
    if (!ACTION_TOOLS.contains(suggestion.getToolCode())) {
      throw new ApiException("该建议没有可执行的安全动作");
    }
    if ("EXECUTED".equals(suggestion.getStatus()) && suggestion.getTaskId() != null) {
      return response(suggestion);
    }

    Long projectId = resolveProjectId(suggestion.getTargetId());

    SecurityTask task =
        tasks.create(
            new CreateTaskRequest(
                projectId, suggestion.getTargetId(), suggestion.getToolCode(), Map.of()));
    suggestion.setTaskId(task.getId());
    suggestion.setStatus("EXECUTED");
    suggestion.setDecidedAt(Instant.now());
    suggestions.save(suggestion);

    TrafficPacket packet = packets.findById(suggestion.getPacketId()).orElseThrow();
    packet.setAiStatus("DONE");
    packets.save(packet);
    audit.record(
        "EXECUTE_TRAFFIC_ACTION",
        "TRAFFIC_SUGGESTION",
        suggestionId,
        "taskId=" + task.getId(),
        "ACCEPTED");
    return response(suggestion);
  }

  private Long resolveProjectId(Long targetId) {
    var links = projectTargets.findByTargetId(targetId);
    if (links.isEmpty()) {
      throw new ApiException("该流量目标未绑定到任何评估项目，无法创建检测任务");
    }
    if (links.size() > 1) {
      throw new ApiException("该流量目标绑定了多个评估项目，请在项目页面手动创建检测任务");
    }
    return links.get(0).getProjectId();
  }

  public void ignore(Long suggestionId) {
    TrafficSuggestion suggestion =
        suggestions.findById(suggestionId).orElseThrow(() -> new ApiException("AI 建议不存在"));
    suggestion.setStatus("IGNORED");
    suggestion.setDecidedAt(Instant.now());
    suggestions.save(suggestion);
    packets
        .findById(suggestion.getPacketId())
        .ifPresent(
            packet -> {
              packet.setAiStatus("IGNORED");
              packets.save(packet);
            });
    audit.record("REJECT_TRAFFIC_ACTION", "TRAFFIC_SUGGESTION", suggestionId, "ignored", "SUCCESS");
  }

  private TrafficSuggestion createSuggestion(TrafficPacket packet) {
    List<String> reasons = new ArrayList<>();
    String severity = "INFO";
    String tool = "http_headers";
    String title = "检查 Web 安全基线";

    if ("CONNECT".equals(packet.getProtocol())) {
      reasons.add("该记录为 HTTPS CONNECT 隧道，当前仅捕获连接元数据。 ");
      tool = "tls_config";
      title = "检查目标 TLS 与证书配置";
    } else {
      String headers =
          packet.getResponseHeaders() == null ? "" : packet.getResponseHeaders().toLowerCase();
      if (!headers.contains("content-security-policy:")) {
        reasons.add("响应中未发现 Content-Security-Policy。 ");
        severity = "MEDIUM";
      }
      if (packet.getStatusCode() != null && packet.getStatusCode() >= 500) {
        reasons.add("服务端返回 5xx，建议结合服务指纹继续确认。 ");
        severity = "MEDIUM";
        tool = "nmap_service_scan";
        title = "识别服务与版本";
      }
      String requestHeaders =
          packet.getRequestHeaders() == null ? "" : packet.getRequestHeaders().toLowerCase();
      String requestBody =
          packet.getRequestBody() == null ? "" : packet.getRequestBody().toLowerCase();
      boolean containsCredentials =
          requestHeaders.contains("authorization:")
              || requestHeaders.contains("cookie:")
              || requestBody.matches(
                  "(?s).*(password|passwd|pwd|token|secret|api[_-]?key|access[_-]?token|"
                      + "refresh[_-]?token|session|credential)\\s*[:=].*");
      if ("http".equalsIgnoreCase(packet.getScheme()) && containsCredentials) {
        reasons.add("明文 HTTP 请求中包含疑似凭据字段。 ");
        severity = "HIGH";
      }
      if (reasons.isEmpty()) {
        reasons.add("未发现直接高危特征，可执行一次低风险 Web 基线检查。 ");
      }
    }

    TrafficSuggestion suggestion = new TrafficSuggestion();
    suggestion.setPacketId(packet.getId());
    suggestion.setTargetId(packet.getTargetId());
    suggestion.setSeverity(severity);
    suggestion.setTitle(title);
    suggestion.setSummary("基于原始请求、响应和连接元数据生成下一步建议。 ");
    suggestion.setReason(String.join("\n", reasons));
    suggestion.setConfidence("HIGH".equals(severity) ? 0.88 : 0.76);
    suggestion.setActionType("PASSIVE_CHECK");
    suggestion.setToolCode(tool);
    suggestion.setRequiresConfirmation(true);
    suggestion.setStatus("PENDING");
    enhanceWithAi(packet, suggestion);
    return suggestions.save(suggestion);
  }

  private void enhanceWithAi(TrafficPacket packet, TrafficSuggestion suggestion) {
    if (!modelClient.enabled()) {
      return;
    }
    try {
      String packetText =
          "method="
              + packet.getMethod()
              + "\nurl="
              + packet.getScheme()
              + "://"
              + packet.getHost()
              + ":"
              + packet.getPort()
              + packet.getPath()
              + "\nstatus="
              + packet.getStatusCode()
              + "\nrequestHeaders=\n"
              + packet.getRequestHeaders()
              + "\nrequestBody=\n"
              + packet.getRequestBody()
              + "\nresponseHeaders=\n"
              + packet.getResponseHeaders()
              + "\nresponseBody=\n"
              + packet.getResponseBody();
      if (packetText.length() > 24_000) {
        packetText = packetText.substring(0, 24_000);
      }
      String content =
          modelClient.complete(
              "你是授权安全测试中的流量分析助手。输入为当前授权范围内的原始抓包内容。"
                  + "请用中文简洁说明风险和下一步验证建议，不得给出漏洞利用、口令尝试、"
                  + "任意命令或扩大授权范围的操作。",
              packetText);
      if (!content.isBlank()) {
        suggestion.setSource("AI");
        suggestion.setSummary(content.length() > 4_000 ? content.substring(0, 4_000) : content);
      }
    } catch (Exception ex) {
      LOGGER.warn("流量建议的 AI 增强失败，流量={}", packet.getId(), ex);
    }
  }

  private AnalysisResponse response(TrafficSuggestion suggestion) {
    return new AnalysisResponse(
        suggestion.getId(),
        suggestion.getSummary(),
        suggestion.getSeverity(),
        List.of(suggestion.getReason().split("\n")),
        List.of(suggestion.getTitle()),
        suggestion.getToolCode() != null
            && suggestion.getTargetId() != null
            && suggestion.getTargetId() > 0,
        suggestion.getStatus(),
        suggestion.getTaskId());
  }

  public record AnalysisResponse(
      Long suggestionId,
      String summary,
      String riskLevel,
      List<String> reasons,
      List<String> nextSteps,
      boolean canAutoHandle,
      String status,
      Long taskId) {}
}
