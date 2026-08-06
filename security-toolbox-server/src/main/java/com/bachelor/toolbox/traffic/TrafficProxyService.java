package com.bachelor.toolbox.traffic;

import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.TargetPolicyService;
import com.bachelor.toolbox.target.TargetService;
import jakarta.annotation.PreDestroy;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

@Service
public class TrafficProxyService {
  private static final Logger LOGGER = LoggerFactory.getLogger(TrafficProxyService.class);
  private static final int PACKET_LIST_LIMIT = 200;
  private static final int CLEANUP_BATCH_SIZE = 200;
  private static final Pageable RECENT_PACKETS =
      PageRequest.of(
          0,
          PACKET_LIST_LIMIT,
          Sort.by(Sort.Direction.DESC, "createdAt")
              .and(Sort.by(Sort.Direction.DESC, "id")));
  private static final Pageable RECENT_SESSION_PACKETS = PageRequest.of(0, PACKET_LIST_LIMIT);
  private static final Pageable CLEANUP_BATCH = PageRequest.of(0, CLEANUP_BATCH_SIZE);

  private final TrafficSessionRepository sessions;
  private final TrafficPacketRepository packets;
  private final TrafficSuggestionRepository suggestions;
  private final TrafficAnalysisService analysis;
  private final TargetService targets;
  private final TargetPolicyService policy;
  private final TrafficCaptureFilterService filters;
  private final AuditService audit;
  private final MitmCertificateAuthority certificateAuthority;
  private final Set<String> autoActions = ConcurrentHashMap.newKeySet();
  private final TransactionTemplate transactions;
  private LocalTrafficProxy proxy;
  private TrafficSession current;
  private volatile boolean capturing;

  public TrafficProxyService(
      TrafficSessionRepository sessions,
      TrafficPacketRepository packets,
      TrafficSuggestionRepository suggestions,
      TrafficAnalysisService analysis,
      TargetService targets,
      TargetPolicyService policy,
      TrafficCaptureFilterService filters,
      AuditService audit,
      MitmCertificateAuthority certificateAuthority,
      PlatformTransactionManager transactionManager) {
    this.sessions = sessions;
    this.packets = packets;
    this.suggestions = suggestions;
    this.analysis = analysis;
    this.targets = targets;
    this.policy = policy;
    this.filters = filters;
    this.audit = audit;
    this.certificateAuthority = certificateAuthority;
    this.transactions = new TransactionTemplate(transactionManager);
  }

  public synchronized Status start(TrafficDtos.StartRequest request) {
    if (proxy != null) {
      throw new ApiException("流量代理已经在运行");
    }
    AuthorizedTarget target = request.targetId() == null ? null : targets.get(request.targetId());
    if (target != null) {
      policy.validatedHost(target);
    }
    int port = request.port() == null ? 19080 : request.port();
    if (port < 19080 || port > 19120) {
      throw new ApiException("代理端口必须在 19080-19120 范围");
    }
    String mode =
        target == null ? "ASK" : request.handlingMode() == null ? "ASK" : request.handlingMode();
    TrafficSession session = new TrafficSession();
    session.setTargetId(target == null ? 0L : target.getId());
    session.setName(target == null ? "通用流量会话" : target.getName() + " 流量会话");
    session.setListenPort(port);
    session.setHandlingMode(mode);
    session.setStatus("STARTING");
    session = sessions.save(session);

    try {
      TrafficSession active = session;
      proxy =
          new LocalTrafficProxy(
              target, policy, certificateAuthority, capture -> saveCapture(active, capture));
      proxy.start(port);
      capturing = false;
      session.setStatus("RUNNING");
      session.setStartedAt(Instant.now());
      current = sessions.save(session);
      audit.record(
          "START_TRAFFIC_PROXY",
          "TRAFFIC_SESSION",
          session.getId(),
          "targetId=" + (target == null ? "NONE" : target.getId()) + ",port=" + port,
          "SUCCESS");
      return status();
    } catch (Exception ex) {
      LOGGER.error("启动流量代理失败，监听端口={}", port, ex);
      session.setStatus("FAILED");
      session.setErrorMessage("启动流量代理失败，请查看服务日志");
      sessions.save(session);
      proxy = null;
      throw new ApiException("启动流量代理失败，请查看服务日志");
    }
  }

  public synchronized Status stop() {
    capturing = false;
    if (proxy != null) {
      proxy.close();
    }
    proxy = null;
    if (current != null) {
      current.setStatus("STOPPED");
      current.setStoppedAt(Instant.now());
      sessions.save(current);
      audit.record("STOP_TRAFFIC_PROXY", "TRAFFIC_SESSION", current.getId(), "stopped", "SUCCESS");
      current = null;
    }
    return status();
  }

  public synchronized Status setCapturing(boolean on) {
    if (proxy == null) {
      throw new ApiException("流量代理尚未启动，无法开始拦截");
    }
    capturing = on;
    audit.record(
        on ? "START_TRAFFIC_CAPTURE" : "STOP_TRAFFIC_CAPTURE",
        "TRAFFIC_SESSION",
        current == null ? null : current.getId(),
        "capturing=" + on,
        "SUCCESS");
    return status();
  }

  public Status status() {
    Long targetId =
        current == null || current.getTargetId() == null || current.getTargetId() <= 0
            ? null
            : current.getTargetId();
    return new Status(
        proxy != null,
        "127.0.0.1",
        current == null ? 19080 : current.getListenPort(),
        current == null ? 0 : current.getPacketCount(),
        targetId,
        current == null ? "ASK" : current.getHandlingMode(),
        certificateAuthority.enabled(),
        certificateAuthority.fingerprint(),
        capturing);
  }

  public List<TrafficPacket> packets() {
    if (current == null) {
      return packets.findAll(RECENT_PACKETS).getContent();
    }
    return packets.findAllBySessionIdOrderByCreatedAtDescIdDesc(
        current.getId(), RECENT_SESSION_PACKETS);
  }

  public TrafficPacket getPacket(Long id) {
    return packets.findById(id).orElseThrow(() -> new ApiException("流量记录不存在"));
  }

  public synchronized TrafficPacket markPacket(Long packetId, boolean marked) {
    TrafficPacket packet = getPacket(packetId);
    packet.setMarked(marked);
    TrafficPacket saved = packets.save(packet);
    audit.record(
        marked ? "MARK_TRAFFIC_PACKET" : "UNMARK_TRAFFIC_PACKET",
        "TRAFFIC_PACKET",
        packetId,
        "marked=" + marked,
        "SUCCESS");
    return saved;
  }

  public synchronized void deletePacket(Long packetId) {
    DeletionResult result =
        transactions.execute(
            ignored -> {
              TrafficPacket packet =
                  packets.findById(packetId).orElseThrow(() -> new ApiException("流量记录不存在"));
              Long sessionId = packet.getSessionId();
              suggestions.findByPacketId(packetId).ifPresent(suggestions::delete);
              suggestions.flush();
              packets.delete(packet);
              packets.flush();
              long remaining = packets.countBySessionId(sessionId);
              sessions
                  .findById(sessionId)
                  .ifPresent(
                      session -> {
                        session.setPacketCount(remaining);
                        sessions.save(session);
                      });
              audit.record(
                  "DELETE_TRAFFIC_PACKET",
                  "TRAFFIC_PACKET",
                  packetId,
                  "sessionId=" + sessionId,
                  "SUCCESS");
              return new DeletionResult(sessionId, remaining);
            });
    if (result != null && current != null && current.getId().equals(result.sessionId())) {
      current.setPacketCount(result.remaining());
    }
  }

  public synchronized void clearPackets() {
    long deletedCount = deleteUnmarkedPacketBatches();
    recountStoredSessions();
    long retainedCount = packets.count();
    if (current != null) {
      current.setPacketCount(packets.countBySessionId(current.getId()));
    }
    transactions.executeWithoutResult(
        ignored ->
            audit.record(
                "CLEAR_TRAFFIC_PACKETS",
                "TRAFFIC_PACKET",
                null,
                "deletedCount=" + deletedCount + ",retainedCount=" + retainedCount,
                "SUCCESS"));
  }

  private long deleteUnmarkedPacketBatches() {
    long total = 0;
    while (true) {
      Integer deleted = transactions.execute(ignored -> deleteUnmarkedPacketBatch());
      if (deleted == null || deleted == 0) {
        return total;
      }
      total += deleted;
    }
  }

  private int deleteUnmarkedPacketBatch() {
    List<TrafficPacket> batch = packets.findAllByMarkedFalseOrderByIdAsc(CLEANUP_BATCH);
    if (batch.isEmpty()) {
      return 0;
    }

    List<Long> packetIds = new ArrayList<>(batch.size());
    Set<Long> sessionIds = new HashSet<>();
    for (TrafficPacket packet : batch) {
      packetIds.add(packet.getId());
      sessionIds.add(packet.getSessionId());
    }

    suggestions.deleteAllByPacketIdIn(packetIds);
    packets.deleteAllInBatch(batch);
    packets.flush();
    recountSessions(sessionIds);
    return batch.size();
  }

  private void recountStoredSessions() {
    long lastId = 0;
    while (true) {
      long cursor = lastId;
      List<Long> refreshedIds =
          transactions.execute(
              ignored -> {
                List<TrafficSession> batch =
                    sessions.findByIdGreaterThanOrderByIdAsc(cursor, CLEANUP_BATCH);
                recountSessions(batch);
                return batch.stream().map(TrafficSession::getId).toList();
              });
      if (refreshedIds == null || refreshedIds.isEmpty()) {
        return;
      }
      lastId = refreshedIds.get(refreshedIds.size() - 1);
    }
  }

  private void recountSessions(Iterable<Long> sessionIds) {
    recountSessions(sessions.findAllById(sessionIds));
  }

  private void recountSessions(List<TrafficSession> sessionBatch) {
    sessionBatch.forEach(
        session -> session.setPacketCount(packets.countBySessionId(session.getId())));
    sessions.saveAll(sessionBatch);
  }

  private synchronized void saveCapture(TrafficSession session, LocalTrafficProxy.Capture capture) {
    if (!capturing || filters.shouldExclude(capture)) {
      return;
    }
    CaptureResult saved = transactions.execute(ignored -> persistCapture(session, capture));
    if (saved == null) {
      return;
    }
    session.setPacketCount(saved.packetCount());
    TrafficPacket packet = saved.packet();
    if (session.getTargetId() != null
        && session.getTargetId() > 0
        && "AUTO_SAFE".equals(session.getHandlingMode())) {
      executeAutomaticSafeAction(session, packet);
    }
  }

  private void executeAutomaticSafeAction(TrafficSession session, TrafficPacket packet) {
    try {
      TrafficAnalysisService.AnalysisResponse result =
          analysis.analyze(packet.getId(), "AUTO_SAFE");
      TrafficSuggestion suggestion = suggestions.findById(result.suggestionId()).orElseThrow();
      boolean supported = Set.of("http_headers", "tls_config").contains(suggestion.getToolCode());
      String actionKey = session.getId() + ":" + suggestion.getToolCode();
      if (supported && autoActions.add(actionKey)) {
        analysis.execute(suggestion.getId());
      }
    } catch (Exception ex) {
      LOGGER.warn("自动安全分析执行失败，会话={}，流量={}", session.getId(), packet.getId(), ex);
    }
  }

  private CaptureResult persistCapture(TrafficSession session, LocalTrafficProxy.Capture capture) {
    TrafficPacket packet = new TrafficPacket();
    packet.setSessionId(session.getId());
    packet.setTargetId(session.getTargetId());
    packet.setProtocol(capture.protocol());
    packet.setMethod(capture.method());
    packet.setScheme(capture.scheme());
    packet.setHost(capture.host());
    packet.setPort(capture.port());
    packet.setPath(capture.path());
    packet.setStatusCode(capture.statusCode());
    packet.setContentType(capture.contentType());
    packet.setRequestBytes(capture.requestBytes());
    packet.setResponseBytes(capture.responseBytes());
    packet.setDurationMs(capture.durationMs());
    packet.setCaptureState(capture.captureState());
    packet.setErrorMessage(capture.errorMessage());
    packet.setRequestHeaders(capture.requestHeaders());
    packet.setRequestBody(capture.requestBody());
    packet.setResponseHeaders(capture.responseHeaders());
    packet.setResponseBody(capture.responseBody());
    packet.setAiStatus("PENDING");
    packet = packets.save(packet);

    TrafficSession stored =
        sessions.findById(session.getId()).orElseThrow(() -> new ApiException("流量会话不存在"));
    long packetCount = stored.getPacketCount() + 1;
    stored.setPacketCount(packetCount);
    sessions.save(stored);
    return new CaptureResult(packet, packetCount);
  }

  @PreDestroy
  public void shutdown() {
    stop();
  }

  private record DeletionResult(Long sessionId, long remaining) {}

  private record CaptureResult(TrafficPacket packet, long packetCount) {}

  public record Status(
      boolean running,
      String listenHost,
      int listenPort,
      long capturedCount,
      Long targetId,
      String handlingMode,
      boolean mitmEnabled,
      String caFingerprint,
      boolean capturing) {}
}
