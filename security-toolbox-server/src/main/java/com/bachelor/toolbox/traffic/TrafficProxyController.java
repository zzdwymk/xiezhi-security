package com.bachelor.toolbox.traffic;

import jakarta.validation.Valid;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

@RestController
@RequestMapping("/api/traffic")
public class TrafficProxyController {
  private static final ExecutorService ZAP_STREAM_EXECUTOR =
      Executors.newCachedThreadPool(
          runnable -> {
            Thread thread = new Thread(runnable, "zap-scan-stream");
            thread.setDaemon(true);
            return thread;
          });

  private final TrafficProxyService proxy;
  private final TrafficAnalysisService analysis;
  private final TrafficReplayService replay;
  private final TrafficCaptureFilterService filters;
  private final TrafficAiChatService chat;
  private final TrafficFuzzService fuzz;
  private final TrafficScanService scanService;
  private final TrafficScanLedgerService scanLedger;

  public TrafficProxyController(
      TrafficProxyService proxy,
      TrafficAnalysisService analysis,
      TrafficReplayService replay,
      TrafficCaptureFilterService filters,
      TrafficAiChatService chat,
      TrafficFuzzService fuzz,
      TrafficScanService scanService,
      TrafficScanLedgerService scanLedger) {
    this.proxy = proxy;
    this.analysis = analysis;
    this.replay = replay;
    this.filters = filters;
    this.chat = chat;
    this.fuzz = fuzz;
    this.scanService = scanService;
    this.scanLedger = scanLedger;
  }

  @GetMapping("/scans")
  public org.springframework.data.domain.Page<TrafficScanLedger> scans(
      @RequestParam(defaultValue = "0") int page,
      @RequestParam(defaultValue = "20") int size,
      @RequestParam(required = false) String engine) {
    return scanLedger.list(page, size, engine);
  }

  @GetMapping("/scans/recent")
  public java.util.List<TrafficScanLedger> recentScans() {
    return scanLedger.recent();
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

  @GetMapping("/fuzz/presets")
  public List<TrafficFuzzService.FuzzPreset> fuzzPresets() {
    return fuzz.getPresets();
  }

  @PostMapping("/packets/{id}/zap-scan")
  public TrafficScanService.TargetedScanResult zapScan(
      @PathVariable Long id, @RequestBody(required = false) TrafficScanService.ZapScanRequest request) {
    return scanService.zapScan(id, request);
  }

  @PostMapping(value = "/packets/{id}/zap-scan/stream", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
  public SseEmitter zapScanStream(
      @PathVariable Long id, @RequestBody(required = false) TrafficScanService.ZapScanRequest request) {
    SseEmitter emitter = new SseEmitter(240_000L);
    ZAP_STREAM_EXECUTOR.execute(
        () -> runStream(emitter, () -> scanService.zapScan(id, request, listenerFor(emitter))));
    emitter.onTimeout(emitter::complete);
    emitter.onError(error -> {});
    return emitter;
  }

  private static void runStream(SseEmitter emitter, ScanAction action) {
    try {
      action.run();
    } catch (Exception ex) {
      try {
        sendEvent(
            emitter, Map.of("type", "error", "message", String.valueOf(ex.getMessage())));
      } catch (Exception ignored) {
        // 客户端已断开，忽略
      }
      emitter.complete();
    }
  }

  @FunctionalInterface
  private interface ScanAction {
    void run() throws Exception;
  }

  private static TrafficScanService.ZapScanListener listenerFor(SseEmitter emitter) {
    return new TrafficScanService.ZapScanListener() {
      @Override
      public void onStart(String targetUrl) {
        sendEvent(emitter, Map.of("type", "start", "targetUrl", targetUrl == null ? "" : targetUrl));
      }

      @Override
      public void onStatus(String message) {
        sendEvent(emitter, Map.of("type", "status", "message", message == null ? "" : message));
      }

      @Override
      public void onProbe(TrafficScanService.TargetedScanProbe probe) {
        sendEvent(emitter, Map.of("type", "probe", "probe", probe));
      }

      @Override
      public void onHit(TrafficScanService.TargetedScanHit hit) {
        sendEvent(emitter, Map.of("type", "hit", "hit", hit));
      }

      @Override
      public void onComplete(TrafficScanService.TargetedScanResult result) {
        sendEvent(emitter, Map.of("type", "complete", "result", result));
        emitter.complete();
      }
    };
  }

  private static void sendEvent(SseEmitter emitter, Map<String, Object> payload) {
    try {
      synchronized (emitter) {
        emitter.send(SseEmitter.event().data(payload, MediaType.APPLICATION_JSON));
      }
    } catch (Exception ex) {
      throw new java.io.UncheckedIOException(new java.io.IOException(ex));
    }
  }

  @PostMapping("/packets/{id}/xray-scan")
  public TrafficScanService.TargetedScanResult xrayScan(
      @PathVariable Long id, @RequestBody(required = false) TrafficScanService.XrayScanRequest request) {
    return scanService.xrayScan(id, request);
  }

  @PostMapping(value = "/packets/{id}/xray-scan/stream", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
  public SseEmitter xrayScanStream(
      @PathVariable Long id, @RequestBody(required = false) TrafficScanService.XrayScanRequest request) {
    SseEmitter emitter = new SseEmitter(240_000L);
    ZAP_STREAM_EXECUTOR.execute(
        () -> runStream(emitter, () -> scanService.xrayScan(id, request, listenerFor(emitter))));
    emitter.onTimeout(emitter::complete);
    emitter.onError(error -> {});
    return emitter;
  }

  @PostMapping("/packets/{id}/sqlmap-scan")
  public TrafficScanService.TargetedScanResult sqlmapScan(
      @PathVariable Long id, @RequestBody(required = false) TrafficScanService.SqlmapScanRequest request) {
    return scanService.sqlmapScan(id, request);
  }

  @PostMapping(value = "/packets/{id}/sqlmap-scan/stream", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
  public SseEmitter sqlmapScanStream(
      @PathVariable Long id, @RequestBody(required = false) TrafficScanService.SqlmapScanRequest request) {
    SseEmitter emitter = new SseEmitter(600_000L);
    ZAP_STREAM_EXECUTOR.execute(
        () -> runStream(emitter, () -> scanService.sqlmapScan(id, request, listenerFor(emitter))));
    emitter.onTimeout(emitter::complete);
    emitter.onError(error -> {});
    return emitter;
  }

  @PostMapping("/packets/{id}/fuzz")
  public TrafficFuzzService.FuzzResponse fuzz(
      @PathVariable Long id, @Valid @RequestBody TrafficFuzzService.FuzzRequest request) {
    return fuzz.fuzz(id, request);
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
