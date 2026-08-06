package com.bachelor.toolbox.traffic;

import jakarta.validation.Valid;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/traffic")
public class TrafficProxyController {
  private final TrafficProxyService proxy;
  private final TrafficAnalysisService analysis;
  private final TrafficReplayService replay;
  private final TrafficCaptureFilterService filters;
  private final TrafficAiChatService chat;

  public TrafficProxyController(
      TrafficProxyService proxy,
      TrafficAnalysisService analysis,
      TrafficReplayService replay,
      TrafficCaptureFilterService filters,
      TrafficAiChatService chat) {
    this.proxy = proxy;
    this.analysis = analysis;
    this.replay = replay;
    this.filters = filters;
    this.chat = chat;
  }

  @GetMapping("/status")
  public TrafficProxyService.Status status() {
    return proxy.status();
  }

  @PostMapping("/proxy/start")
  public TrafficProxyService.Status start(@Valid @RequestBody TrafficDtos.StartRequest request) {
    return proxy.start(request);
  }

  @PostMapping("/proxy/stop")
  public TrafficProxyService.Status stop() {
    return proxy.stop();
  }

  @PostMapping("/proxy/capture")
  public TrafficProxyService.Status capture(@RequestBody Map<String, Boolean> body) {
    return proxy.setCapturing(Boolean.TRUE.equals(body.get("enabled")));
  }

  @GetMapping("/sessions")
  public List<PacketView> packets() {
    return proxy.packets().stream().map(PacketView::from).toList();
  }

  @PutMapping("/sessions/{packetId}/marked")
  public PacketView markPacket(@PathVariable Long packetId, @RequestBody MarkRequest request) {
    return PacketView.from(proxy.markPacket(packetId, request.marked()));
  }

  @DeleteMapping("/sessions/{packetId}")
  @ResponseStatus(HttpStatus.NO_CONTENT)
  public void deletePacket(@PathVariable Long packetId) {
    proxy.deletePacket(packetId);
  }

  @DeleteMapping("/sessions")
  @ResponseStatus(HttpStatus.NO_CONTENT)
  public void clearPackets() {
    proxy.clearPackets();
  }

  @GetMapping("/packets/{id}")
  public PacketView packet(@PathVariable Long id) {
    return PacketView.from(proxy.getPacket(id));
  }

  @PostMapping("/packets/{id}/replay")
  public TrafficReplayService.ReplayResponse replay(
      @PathVariable Long id, @Valid @RequestBody TrafficReplayService.ReplayRequest request) {
    return replay.replay(id, request);
  }

  @PostMapping("/packets/{id}/chat")
  public TrafficAiChatService.ChatResponse chat(
      @PathVariable Long id, @Valid @RequestBody TrafficAiChatService.ChatRequest request) {
    return chat.chat(id, request);
  }

  @PostMapping("/sessions/{packetId}/analyze")
  public TrafficAnalysisService.AnalysisResponse analyze(
      @PathVariable Long packetId, @RequestBody(required = false) Map<String, Object> body) {
    String mode =
        String.valueOf(body == null ? "SUGGEST_ONLY" : body.getOrDefault("mode", "SUGGEST_ONLY"));
    return analysis.analyze(packetId, mode);
  }

  @PostMapping("/suggestions/{id}/execute")
  public TrafficAnalysisService.AnalysisResponse execute(@PathVariable Long id) throws Exception {
    return analysis.execute(id);
  }

  @PostMapping("/suggestions/{id}/ignore")
  public void ignore(@PathVariable Long id) {
    analysis.ignore(id);
  }

  @GetMapping("/filters")
  public List<TrafficCaptureFilter> filters() {
    return filters.list();
  }

  @PostMapping("/filters")
  @ResponseStatus(HttpStatus.CREATED)
  public TrafficCaptureFilter createFilter(
      @Valid @RequestBody TrafficCaptureFilterService.FilterRequest request) {
    return filters.create(request);
  }

  @PutMapping("/filters/{id}")
  public TrafficCaptureFilter updateFilter(
      @PathVariable Long id,
      @Valid @RequestBody TrafficCaptureFilterService.FilterRequest request) {
    return filters.update(id, request);
  }

  @DeleteMapping("/filters/{id}")
  @ResponseStatus(HttpStatus.NO_CONTENT)
  public void deleteFilter(@PathVariable Long id) {
    filters.delete(id);
  }

  public record MarkRequest(boolean marked) {}

  public record PacketView(
      Long id,
      Long sessionId,
      Long targetId,
      String protocol,
      String method,
      String scheme,
      String url,
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
      boolean marked,
      String requestHeaders,
      String responseHeaders,
      String requestBody,
      String responseBody,
      String captureState,
      String errorMessage,
      Instant createdAt) {
    static PacketView from(TrafficPacket packet) {
      String url =
          (packet.getScheme() == null ? "http" : packet.getScheme())
              + "://"
              + packet.getHost()
              + (packet.getPort() == 80 || packet.getPort() == 443 ? "" : ":" + packet.getPort())
              + (packet.getPath() == null ? "" : packet.getPath());
      return new PacketView(
          packet.getId(),
          packet.getSessionId(),
          packet.getTargetId(),
          packet.getProtocol(),
          packet.getMethod(),
          packet.getScheme(),
          url,
          packet.getHost(),
          packet.getPort(),
          packet.getPath(),
          packet.getStatusCode(),
          packet.getContentType(),
          packet.getRequestBytes(),
          packet.getResponseBytes(),
          packet.getDurationMs(),
          packet.getRiskLevel(),
          packet.getAiStatus(),
          packet.isMarked(),
          packet.getRequestHeaders(),
          packet.getResponseHeaders(),
          packet.getRequestBody(),
          packet.getResponseBody(),
          packet.getCaptureState(),
          packet.getErrorMessage(),
          packet.getCreatedAt());
    }
  }
}
