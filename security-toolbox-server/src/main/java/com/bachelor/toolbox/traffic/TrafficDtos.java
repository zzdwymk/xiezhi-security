package com.bachelor.toolbox.traffic;

import jakarta.validation.constraints.Pattern;
import java.time.Instant;

public final class TrafficDtos {
  private TrafficDtos() {}

  public record StartRequest(
      Long targetId,
      Integer port,
      @Pattern(regexp = "ASK|AUTO_SAFE", message = "流量处理模式仅支持 ASK 或 AUTO_SAFE")
          String handlingMode) {}

  public record DecisionRequest(
      @Pattern(regexp = "EXECUTE|IGNORE", message = "流量处理决定仅支持 EXECUTE 或 IGNORE")
          String decision) {}

  public record PacketSummary(
      Long id,
      Long sessionId,
      Long targetId,
      String protocol,
      String method,
      String scheme,
      String host,
      int port,
      String path,
      Integer statusCode,
      String contentType,
      long requestBytes,
      long responseBytes,
      Long durationMs,
      String riskLevel,
      String aiStatus,
      Instant createdAt) {}

  public record PacketDetail(
      PacketSummary packet,
      String requestHeaders,
      String requestBody,
      String responseHeaders,
      String responseBody,
      String captureState,
      String errorMessage) {}
}
