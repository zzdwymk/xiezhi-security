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
        reasons.add("ZAP被动审计：响应中未配置 Content-Security-Policy (CSP)。 ");
        severity = "MEDIUM";
      }
      if (!headers.contains("x-content-type-options:")) {
        reasons.add("ZAP被动审计：缺失 X-Content-Type-Options: nosniff 防御响应头。 ");
        if ("INFO".equals(severity)) severity = "LOW";
      }
      if (!headers.contains("x-frame-options:") && !headers.contains("frame-ancestors")) {
        reasons.add("ZAP被动审计：缺失 X-Frame-Options 点击劫持防护头。 ");
        if ("INFO".equals(severity)) severity = "LOW";
      }
      if ("https".equalsIgnoreCase(packet.getScheme()) && !headers.contains("strict-transport-security:")) {
        reasons.add("ZAP被动审计：HTTPS 站点缺失 Strict-Transport-Security (HSTS) 头。 ");
        if ("INFO".equals(severity)) severity = "LOW";
      }

      // CORS 缺陷
      if (headers.contains("access-control-allow-origin: *") && headers.contains("access-control-allow-credentials: true")) {
        reasons.add("ZAP被动审计：CORS 跨域策略缺陷，通配符 Origin 允许携带认证凭据。 ");
        severity = "HIGH";
        title = "CORS 跨域资源共享高危配置";
      }

      // Cookie 安全标记
      if (headers.contains("set-cookie:")) {
        for (String line : headers.split("\\r?\\n")) {
          if (line.startsWith("set-cookie:")) {
            if (!line.contains("httponly")) {
              reasons.add("ZAP被动审计：Set-Cookie 缺失 HttpOnly 属性，易受 XSS 劫持。 ");
              if ("INFO".equals(severity)) severity = "LOW";
            }
            if ("https".equalsIgnoreCase(packet.getScheme()) && !line.contains("secure")) {
              reasons.add("ZAP被动审计：HTTPS 环境下 Set-Cookie 缺失 Secure 属性。 ");
              if ("INFO".equals(severity)) severity = "LOW";
            }
            if (!line.contains("samesite")) {
              reasons.add("ZAP被动审计：Set-Cookie 缺失 SameSite 属性。 ");
              if ("INFO".equals(severity)) severity = "LOW";
            }
          }
        }
      }

      // 响应敏感信息泄露
      String respBody = packet.getResponseBody() == null ? "" : packet.getResponseBody();
      if (!respBody.isEmpty() && respBody.length() < 200_000) {
        if (respBody.matches("(?s).*(Exception in thread|Traceback \\(most recent call last\\)|org\\.springframework\\.|NullPointerException|SQLException|SQLSTATE\\[).*")) {
          reasons.add("ZAP被动审计：响应体中包含服务端详细报错或异常堆栈追踪信息。 ");
          severity = "HIGH".equals(severity) ? "HIGH" : "MEDIUM";
          title = "服务端详细错误与堆栈泄露";
        }
        if (respBody.matches("(?s).*\\b(10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}|172\\.(1[6-9]|2\\d|3[01])\\.\\d{1,3}\\.\\d{1,3}|192\\.168\\.\\d{1,3}\\.\\d{1,3})\\b.*")) {
          reasons.add("ZAP被动审计：响应体中包含局域网私有 IPv4 地址泄露。 ");
          if ("INFO".equals(severity)) severity = "LOW";
        }
      }

      if (packet.getStatusCode() != null && packet.getStatusCode() >= 500) {
        reasons.add("服务端返回 5xx 状态码，建议结合服务指纹继续确认。 ");
        if ("INFO".equals(severity) || "LOW".equals(severity)) severity = "MEDIUM";
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
        title = "明文传输敏感认证凭据";
      }
      if (reasons.isEmpty()) {
        reasons.add("未发现直接高危特征，可执行一次低风险 Web 基线检查。 ");
      }
    }

    packet.setRiskLevel(severity);
    packets.save(packet);

    TrafficSuggestion suggestion = new TrafficSuggestion();
    suggestion.setPacketId(packet.getId());
    suggestion.setTargetId(packet.getTargetId());
    suggestion.setSource("ZAP_PASSIVE");
    suggestion.setSeverity(severity);
    suggestion.setTitle(title);
    suggestion.setSummary("基于 ZAP 协议被动分析与原始请求/响应规则审查生成建议。 ");
    suggestion.setReason(String.join("\n", reasons));
    suggestion.setConfidence("HIGH".equals(severity) ? 0.90 : "MEDIUM".equals(severity) ? 0.82 : 0.75);
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
