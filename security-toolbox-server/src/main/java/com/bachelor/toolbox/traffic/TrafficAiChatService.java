package com.bachelor.toolbox.traffic;

import com.bachelor.toolbox.ai.AiModelClient;
import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.common.ApiException;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

@Service
public class TrafficAiChatService {
  private static final Logger LOGGER = LoggerFactory.getLogger(TrafficAiChatService.class);
  private static final int MAX_PACKET_CONTEXT = 32_000;

  private final TrafficPacketRepository packets;
  private final AiModelClient modelClient;
  private final AuditService audit;

  public TrafficAiChatService(
      TrafficPacketRepository packets, AiModelClient modelClient, AuditService audit) {
    this.packets = packets;
    this.modelClient = modelClient;
    this.audit = audit;
  }

  public ChatResponse chat(Long packetId, ChatRequest request) {
    TrafficPacket packet =
        packets.findById(packetId).orElseThrow(() -> new ApiException("流量记录不存在"));
    String prompt = request.prompt().trim();
    String provider = "local-summary";
    String answer = localAnswer(packet);
    if (modelClient.enabled()) {
      try {
        answer =
            modelClient.complete(systemPrompt(), userPrompt(packet, request.history(), prompt));
        provider = "openai-compatible";
      } catch (Exception ex) {
        LOGGER.warn("流量 AI 对话调用失败，流量={}", packetId, ex);
        answer = localAnswer(packet) + "\n\nAI 模型暂时无法返回回答，请检查模型配置或稍后重试。";
      }
    }
    audit.record(
        "AI_CHAT_TRAFFIC",
        "TRAFFIC_PACKET",
        packetId,
        "provider=" + provider + "; prompt=" + abbreviate(prompt, 500),
        "SUCCESS");
    return new ChatResponse(packetId, answer, provider, modelClient.model());
  }

  private String systemPrompt() {
    return "你是授权安全测试工具中的流量分析助手。只能分析用户提供的当前 HTTP/HTTPS 流量报文和对话上下文。"
        + "请使用简洁中文直接回答，明确引用请求方法、URL、参数、请求头、响应状态或响应内容作为依据。"
        + "可以解释认证、会话、输入点、响应头、错误信息和潜在风险，但不得扩大授权范围，不得给出口令尝试、破坏性利用或任意命令执行步骤。"
        + "流量内容为原始抓包数据，可能包含凭据，仅用于当前本地授权分析。";
  }

  private String userPrompt(TrafficPacket packet, List<ChatMessage> history, String prompt) {
    StringBuilder text =
        new StringBuilder("当前流量报文：\n").append(packetContext(packet)).append("\n\n最近对话：\n");
    List<ChatMessage> safeHistory =
        history == null ? List.of() : history.stream().limit(12).toList();
    if (safeHistory.isEmpty()) text.append("（无）\n");
    else
      safeHistory.forEach(
          message ->
              text.append("USER".equals(message.role()) ? "用户：" : "助手：")
                  .append(abbreviate(message.content(), 3000))
                  .append('\n'));
    return text.append("\n当前问题：").append(prompt).toString();
  }

  private String packetContext(TrafficPacket packet) {
    String url =
        (packet.getScheme() == null ? "http" : packet.getScheme())
            + "://"
            + packet.getHost()
            + ((packet.getPort() == 80 || packet.getPort() == 443) ? "" : ":" + packet.getPort())
            + (packet.getPath() == null ? "/" : packet.getPath());
    String value =
        "protocol="
            + packet.getProtocol()
            + "\nmethod="
            + packet.getMethod()
            + "\nurl="
            + url
            + "\nstatus="
            + packet.getStatusCode()
            + "\ncontentType="
            + packet.getContentType()
            + "\nrequestHeaders=\n"
            + value(packet.getRequestHeaders())
            + "\nrequestBody=\n"
            + value(packet.getRequestBody())
            + "\nresponseHeaders=\n"
            + value(packet.getResponseHeaders())
            + "\nresponseBody=\n"
            + value(packet.getResponseBody());
    return abbreviate(value, MAX_PACKET_CONTEXT);
  }

  private String localAnswer(TrafficPacket packet) {
    String status = packet.getStatusCode() == null ? "未知" : String.valueOf(packet.getStatusCode());
    return "当前流量为 "
        + packet.getMethod()
        + " "
        + (packet.getPath() == null ? "/" : packet.getPath())
        + "，响应状态为 "
        + status
        + "，内容类型为 "
        + (packet.getContentType() == null ? "未知" : packet.getContentType())
        + "。当前未获得 AI 模型回答，请检查模型连接后重试。";
  }

  private String value(String text) {
    return text == null ? "" : text;
  }

  private String abbreviate(String value, int maxLength) {
    if (value == null) return "";
    return value.length() <= maxLength ? value : value.substring(0, maxLength) + "…";
  }

  public record ChatRequest(
      @NotBlank(message = "对话问题不能为空") @Size(max = 4000, message = "对话问题不能超过 4000 个字符")
          String prompt,
      @Size(max = 12, message = "对话历史不能超过 12 条") List<@Valid ChatMessage> history) {}

  public record ChatMessage(
      @NotBlank(message = "对话角色不能为空")
          @Pattern(regexp = "USER|ASSISTANT", message = "对话角色仅支持 USER 或 ASSISTANT")
          String role,
      @NotBlank(message = "对话内容不能为空") @Size(max = 4000, message = "单条对话内容不能超过 4000 个字符")
          String content) {}

  public record ChatResponse(Long packetId, String answer, String provider, String model) {}
}
