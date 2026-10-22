package com.bachelor.toolbox.ai;

import com.bachelor.toolbox.common.ApiException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.langchain4j.data.message.AiMessage;
import dev.langchain4j.data.message.UserMessage;
import dev.langchain4j.memory.ChatMemory;
import dev.langchain4j.memory.chat.MessageWindowChatMemory;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Deque;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/**
 * Bounded, process-local conversation memory backed by LangChain4j.
 *
 * <p>Sessions are bound to one project and target. Reusing a session id for another scope is
 * rejected so previous context cannot be confused with a different authorization boundary.
 */
@Service
public class AiConversationMemoryService {
  private static final int MAX_TRANSCRIPT_CHARS = 8_000;

  private final ConcurrentHashMap<String, Session> sessions = new ConcurrentHashMap<>();
  private final Object lifecycleMonitor = new Object();
  private final int maxMessages;
  private final int maxSessions;
  private final Duration ttl;
  private final AiConversationSessionRepository repository;
  private final ObjectMapper objectMapper;
  private final AiAgentRuntimeClient runtimeClient;

  @Autowired
  public AiConversationMemoryService(
      @Value("${toolbox.ai.agent.memory-messages:20}") int maxMessages,
      @Value("${toolbox.ai.agent.max-sessions:200}") int maxSessions,
      @Value("${toolbox.ai.agent.session-ttl-minutes:120}") long ttlMinutes,
      AiConversationSessionRepository repository,
      ObjectMapper objectMapper,
      AiAgentRuntimeClient runtimeClient) {
    this.maxMessages = Math.max(4, Math.min(maxMessages, 100));
    this.maxSessions = Math.max(10, Math.min(maxSessions, 2_000));
    this.ttl = Duration.ofMinutes(Math.max(5, Math.min(ttlMinutes, 24 * 60)));
    this.repository = repository;
    this.objectMapper = objectMapper;
    this.runtimeClient = runtimeClient;
  }

  AiConversationMemoryService(int maxMessages, int maxSessions, long ttlMinutes) {
    this(maxMessages, maxSessions, ttlMinutes, null, new ObjectMapper(), null);
  }

  public SessionHandle open(String requestedId, Long projectId, Long targetId) {
    if (projectId == null || targetId == null) {
      throw new ApiException("AI 会话必须绑定评估项目和授权目标");
    }
    String id =
        requestedId == null || requestedId.isBlank() ? UUID.randomUUID().toString() : requestedId;
    if (!id.matches("[A-Za-z0-9_-]{1,64}")) {
      throw new ApiException("AI 会话编号格式不合法");
    }
    Session session;
    List<RuntimeCleanup> pendingCleanups;
    synchronized (lifecycleMonitor) {
      // evictExpired 由 open() 在每一轮对话中调用，而这里持有全局 lifecycleMonitor。
      // 它只负责在锁内登记待清理项，真正的 HTTP 清理必须等出锁后再做，
      // 否则一次慢调用就会占住全局锁，阻塞所有会话的对话。
      pendingCleanups = evictExpired();
      if (!sessions.containsKey(id)) {
        loadPersisted(id);
      }
      if (!sessions.containsKey(id)) {
        pendingCleanups.addAll(evictAtCapacity());
      }
      Session existing = sessions.get(id);
      if (existing != null) {
        session = existing;
      } else {
        // 先落库再登记：若 persist 抛错，绝不能把这个空的 Session 留在 sessions 里。
        // 否则重试时第 76 行判断为"已存在"而跳过 loadPersisted，历史会被空列表覆盖，
        // 造成静默的上下文丢失。
        Session created = new Session(projectId, targetId, maxMessages);
        synchronized (created.monitor) {
          created.lastAccess = Instant.now();
          try {
            persist(id, created);
          } catch (RuntimeException ex) {
            sessions.remove(id, created);
            throw ex;
          }
          sessions.put(id, created);
        }
        session = created;
      }
      synchronized (session.monitor) {
        if (!projectId.equals(session.projectId) || !targetId.equals(session.targetId)) {
          throw new ApiException("AI 会话已绑定其他项目或目标，请新建会话");
        }
        session.lastAccess = Instant.now();
        persist(id, session);
      }
    }
    // 已出锁：此时才真正发起运行时记忆清理。
    flushRuntimeCleanups(pendingCleanups);
    return new SessionHandle(id, session.monitor, session.projectId, session.targetId);
  }

  public SessionScope scope(String sessionId) {
    if (sessionId == null || !sessionId.matches("[A-Za-z0-9_-]{1,64}")) return null;
    Session session = sessions.get(sessionId);
    if (session != null) {
      synchronized (session.monitor) {
        if (sessions.get(sessionId) != session) return null;
        return new SessionScope(session.projectId, session.targetId);
      }
    }
    if (repository == null) return null;
    AiConversationSessionRecord record = repository.findById(sessionId).orElse(null);
    return record == null ? null : new SessionScope(record.getProjectId(), record.getTargetId());
  }

  public String transcript(String sessionId) {
    Session session = require(sessionId);
    synchronized (session.monitor) {
      ensureCurrent(sessionId, session);
      session.lastAccess = Instant.now();
      Deque<String> recent = new ArrayDeque<>();
      int characters = 0;
      boolean truncated = false;
      var turns = session.turns.descendingIterator();
      while (turns.hasNext()) {
        Turn turn = turns.next();
        String line = (turn.user ? "用户" : "助手") + "：" + turn.text + "\n";
        if (characters + line.length() > MAX_TRANSCRIPT_CHARS) {
          truncated = true;
          break;
        }
        // Budget from the newest end, then restore chronological order without slicing turns.
        recent.addFirst(line);
        characters += line.length();
      }
      StringBuilder output = new StringBuilder();
      if (truncated) output.append("（历史较长，较早的内容已省略）\n");
      recent.forEach(output::append);
      persist(sessionId, session);
      return output.toString().strip();
    }
  }

  /** Structured turns for the AI runtime planner (role/content only). */
  public List<Map<String, String>> recentChatMessages(String sessionId) {
    Session session = require(sessionId);
    synchronized (session.monitor) {
      ensureCurrent(sessionId, session);
      session.lastAccess = Instant.now();
      List<Map<String, String>> out = new ArrayList<>();
      for (Turn turn : session.turns) {
        Map<String, String> item = new LinkedHashMap<>();
        item.put("role", turn.user ? "user" : "assistant");
        item.put("content", turn.text);
        out.add(item);
      }
      persist(sessionId, session);
      return out;
    }
  }

  public void addUser(String sessionId, String text) {
    Session session = require(sessionId);
    synchronized (session.monitor) {
      ensureCurrent(sessionId, session);
      String safe = safeText(text);
      session.memory.add(UserMessage.from(safe));
      addTurn(session, new Turn(true, safe));
      persist(sessionId, session);
    }
  }

  public void addAssistant(String sessionId, String text) {
    Session session = require(sessionId);
    synchronized (session.monitor) {
      ensureCurrent(sessionId, session);
      String safe = safeText(text);
      session.memory.add(AiMessage.from(safe));
      addTurn(session, new Turn(false, safe));
      persist(sessionId, session);
    }
  }

  public int messageCount(String sessionId) {
    Session session = require(sessionId);
    synchronized (session.monitor) {
      ensureCurrent(sessionId, session);
      return session.memory.messages().size();
    }
  }

  String deliveredPlan(String sessionId) {
    Session session = require(sessionId);
    synchronized (session.monitor) {
      ensureCurrent(sessionId, session);
      return session.lastPlanJson;
    }
  }

  /** Structured digest of compacted turns, or null when the session has never compacted. */
  String conversationSummary(String sessionId) {
    Session session = require(sessionId);
    synchronized (session.monitor) {
      ensureCurrent(sessionId, session);
      return session.summaryJson;
    }
  }

  /**
   * Persist the digest produced by the runtime for the next turn. An older digest is kept if the
   * new one is absent, so a turn that did not compact cannot erase earlier recall.
   */
  void saveConversationSummary(String sessionId, String summaryJson) {
    if (summaryJson == null || summaryJson.isBlank()) return;
    Session session = require(sessionId);
    synchronized (session.monitor) {
      ensureCurrent(sessionId, session);
      String previous = session.summaryJson;
      session.summaryJson = summaryJson;
      try {
        persist(sessionId, session);
      } catch (RuntimeException ex) {
        session.summaryJson = previous;
        throw ex;
      }
    }
  }

  void saveDeliveredPlan(String sessionId, String planJson) {    Session session = require(sessionId);
    synchronized (session.monitor) {
      ensureCurrent(sessionId, session);
      String previous = session.lastPlanJson;
      session.lastPlanJson = planJson;
      try {
        persist(sessionId, session);
      } catch (RuntimeException ex) {
        session.lastPlanJson = previous;
        throw ex;
      }
    }
  }

  public SessionScope clear(String sessionId) {
    if (sessionId == null) return null;
    // clearRuntimeMemory 会同步调用 AI Runtime 的索引清理接口（读超时可达 10 秒以上）。
    // 它必须在锁外执行：否则一次慢调用会长时间占住 lifecycleMonitor / session.monitor，
    // 使 DELETE 会话请求挂起直到浏览器放弃（表现为 net::ERR_ABORTED、会话数不减少），
    // 并连带阻塞同一会话上的其他操作。
    Long runtimeProjectId;
    SessionScope scope;
    synchronized (lifecycleMonitor) {
      Session removed = sessions.get(sessionId);
      if (removed != null) {
        synchronized (removed.monitor) {
          sessions.remove(sessionId, removed);
          removed.memory.clear();
          removed.turns.clear();
          deletePersisted(sessionId);
        }
        runtimeProjectId = removed.projectId;
        scope = new SessionScope(removed.projectId, removed.targetId);
      } else {
        AiConversationSessionRecord persisted =
            repository == null ? null : repository.findById(sessionId).orElse(null);
        if (persisted == null) return null;
        repository.delete(persisted);
        runtimeProjectId = persisted.getProjectId();
        scope = new SessionScope(persisted.getProjectId(), persisted.getTargetId());
      }
    }
    // 锁外做"尽力而为"的运行时记忆清理，失败不影响本地删除结果。
    clearRuntimeMemory(runtimeProjectId, sessionId);
    return scope;
  }

  private void addTurn(Session session, Turn turn) {
    session.turns.addLast(turn);
    while (session.turns.size() > maxMessages) session.turns.removeFirst();
    session.lastAccess = Instant.now();
  }

  private Session require(String id) {
    Session session = sessions.get(id);
    if (session == null) throw new ApiException("AI 会话不存在或已过期");
    return session;
  }

  /** Drops process-local session state after the durable session rows have been cleared. */
  public void evictAllLocal() {
    synchronized (lifecycleMonitor) {
      sessions.values().forEach(
          session -> {
            synchronized (session.monitor) {
              session.memory.clear();
              session.turns.clear();
            }
          });
      sessions.clear();
    }
  }

  private void ensureCurrent(String id, Session session) {
    if (sessions.get(id) != session) throw new ApiException("AI 会话不存在或已过期");
  }

  private List<RuntimeCleanup> evictExpired() {
    Instant threshold = Instant.now().minus(ttl);
    // clearRuntimeMemory 会同步调用 AI Runtime 的索引清理接口（读超时可达 120 秒）。
    // 它必须在所有锁之外执行：evictExpired 由 open() 在每一轮对话中调用，
    // 而 open() 本身持有 lifecycleMonitor。若在这里同步发 HTTP，一次慢调用就会
    // 占住这个全局锁，阻塞所有会话的对话（与 clear() 曾出现的缺陷同一类）。
    // 因此先在锁内收集待清理项，出锁后统一处理。
    List<RuntimeCleanup> cleanups = new ArrayList<>();
    for (Map.Entry<String, Session> entry : sessions.entrySet()) {
      String id = entry.getKey();
      Session session = entry.getValue();
      if (!session.lastAccess.isBefore(threshold)) continue;
      synchronized (session.monitor) {
        if (sessions.get(id) != session || !session.lastAccess.isBefore(threshold)) continue;
        if (sessions.remove(id, session)) {
          deletePersisted(id);
          cleanups.add(new RuntimeCleanup(session.projectId, id));
        }
      }
    }
    if (repository != null) {
      // 同一会话可能既在内存中被移除、又出现在这条持久化查询里（deletePersisted 之后
      // 查询结果仍可能是移除前的快照）。用 already 去重，避免对同一会话重复发起清理。
      Set<String> already = new HashSet<>();
      for (RuntimeCleanup cleanup : cleanups) already.add(cleanup.sessionId());
      repository.findByLastAccessBefore(threshold).stream()
          .filter(record -> !sessions.containsKey(record.getId()))
          .filter(record -> already.add(record.getId()))
          .forEach(
              record -> {
                repository.delete(record);
                cleanups.add(new RuntimeCleanup(record.getProjectId(), record.getId()));
              });
    }
    return cleanups;
  }

  /** 待清理的运行时记忆：锁内只登记，锁外才真正发起 HTTP。 */
  private record RuntimeCleanup(long projectId, String sessionId) {}

  private List<RuntimeCleanup> evictAtCapacity() {
    List<RuntimeCleanup> cleanups = new ArrayList<>();
    if (repository != null) {
      while (repository.count() >= maxSessions) {
        AiConversationSessionRecord oldest =
            repository.findFirstByOrderByLastAccessAsc().orElse(null);
        if (oldest == null) break;
        Session session = sessions.get(oldest.getId());
        if (session == null) {
          repository.delete(oldest);
          cleanups.add(new RuntimeCleanup(oldest.getProjectId(), oldest.getId()));
          continue;
        }
        synchronized (session.monitor) {
          if (sessions.get(oldest.getId()) != session) continue;
          AiConversationSessionRecord refreshedOldest =
              repository.findFirstByOrderByLastAccessAsc().orElse(null);
          if (refreshedOldest == null) break;
          if (!oldest.getId().equals(refreshedOldest.getId())) continue;
          if (sessions.remove(oldest.getId(), session)) {
            repository.delete(refreshedOldest);
            cleanups.add(
                new RuntimeCleanup(refreshedOldest.getProjectId(), refreshedOldest.getId()));
          }
        }
      }
      return cleanups;
    }
    while (sessions.size() >= maxSessions) {
      Map.Entry<String, Session> oldest =
          sessions.entrySet().stream()
              .min(Comparator.comparing(entry -> entry.getValue().lastAccess))
              .orElse(null);
      if (oldest == null) break;
      Session session = oldest.getValue();
      synchronized (session.monitor) {
        if (sessions.get(oldest.getKey()) != session) continue;
        Map.Entry<String, Session> refreshedOldest =
            sessions.entrySet().stream()
                .min(Comparator.comparing(entry -> entry.getValue().lastAccess))
                .orElse(null);
        if (refreshedOldest == null) break;
        if (refreshedOldest.getValue() != session) continue;
        if (sessions.remove(oldest.getKey(), session)) {
          cleanups.add(new RuntimeCleanup(session.projectId, oldest.getKey()));
        }
      }
    }
    return cleanups;
  }

  /** 在锁外统一执行运行时记忆清理，避免阻塞 lifecycleMonitor / session.monitor。 */
  private void flushRuntimeCleanups(List<RuntimeCleanup> cleanups) {
    for (RuntimeCleanup cleanup : cleanups) {
      clearRuntimeMemory(cleanup.projectId(), cleanup.sessionId());
    }
  }

  private void loadPersisted(String id) {
    if (repository == null) return;
    AiConversationSessionRecord record = repository.findById(id).orElse(null);
    if (record == null) return;
    if (record.getLastAccess().isBefore(Instant.now().minus(ttl))) {
      repository.delete(record);
      clearRuntimeMemory(record.getProjectId(), record.getId());
      return;
    }
    Session session = new Session(record.getProjectId(), record.getTargetId(), maxMessages);
    session.lastPlanJson = record.getLastPlanJson();
    session.summaryJson = record.getSummaryJson();
    session.usage = parseUsage(record.getUsageJson());
    try {
      List<PersistedTurn> persistedTurns =
          objectMapper.readValue(record.getTurnsJson(), new TypeReference<List<PersistedTurn>>() {});
      for (PersistedTurn turn : persistedTurns) {
        String text = safeText(turn.text());
        if (turn.user()) session.memory.add(UserMessage.from(text));
        else session.memory.add(AiMessage.from(text));
        addTurn(session, new Turn(turn.user(), text));
      }
      session.lastAccess = record.getLastAccess();
      sessions.putIfAbsent(id, session);
    } catch (Exception ex) {
      repository.delete(record);
      clearRuntimeMemory(record.getProjectId(), record.getId());
    }
  }

  private synchronized void persist(String id, Session session) {
    if (repository == null) return;
    try {
      AiConversationSessionRecord record =
          repository
              .findById(id)
              .orElseGet(
                  () -> {
                    AiConversationSessionRecord r = new AiConversationSessionRecord();
                    r.setId(id);
                    r.setCreatedAt(Instant.now());
                    return r;
                  });
      record.setProjectId(session.projectId);
      record.setTargetId(session.targetId);
      record.setLastAccess(session.lastAccess);
      record.setLastPlanJson(session.lastPlanJson);
      record.setSummaryJson(session.summaryJson);
      record.setUsageJson(session.usage == null ? null : objectMapper.writeValueAsString(session.usage));
      record.setTurnsJson(
          objectMapper.writeValueAsString(
              session.turns.stream()
                  .map(turn -> new PersistedTurn(turn.user(), turn.text()))
                  .toList()));
      repository.save(record);
    } catch (Exception ex) {
      throw new ApiException("AI 会话记忆暂时不可写");
    }
  }

  private void deletePersisted(String id) {
    if (repository != null) repository.findById(id).ifPresent(repository::delete);
  }

  private void clearRuntimeMemory(Long projectId, String conversationId) {
    if (runtimeClient != null && projectId != null) {
      runtimeClient.clearConversationMemories(projectId, conversationId);
    }
  }

  public Map<String, Object> usage(String sessionId) {
    if (sessionId == null || !sessionId.matches("[A-Za-z0-9_-]{1,64}")) return Map.of();
    Session session = sessions.get(sessionId);
    if (session != null) {
      synchronized (session.monitor) {
        return session.usage == null ? Map.of() : java.util.Collections.unmodifiableMap(new LinkedHashMap<>(session.usage));
      }
    }
    if (repository == null) return Map.of();
    AiConversationSessionRecord record = repository.findById(sessionId).orElse(null);
    return record == null ? Map.of()
        : java.util.Collections.unmodifiableMap(new LinkedHashMap<>(parseUsage(record.getUsageJson())));
  }

  public void addModelUsage(String sessionId, Map<String, Object> usage) {
    if (usage == null || usage.isEmpty()) return;
    Session session = require(sessionId);
    synchronized (session.monitor) {
      Map<String, Object> previousUsage = session.usage;
      Instant previousLastAccess = session.lastAccess;
      Map<String, Object> aggregate = new LinkedHashMap<>(session.usage == null ? Map.of() : session.usage);
      Set<String> requiredKeys = Set.of("available", "source", "model", "modelCalls", "providerReportedCalls",
          "estimatedCalls", "cacheReportedCalls", "inputTokens", "outputTokens", "totalTokens",
          "cachedInputTokens", "cacheWriteTokens", "reasoningTokens", "estimatedInputTokens",
          "cacheHitRatePermille", "contextWindowTokens", "contextWindowSource", "contextWindowUsedTokens",
          "contextWindowUsagePermille", "peakInputTokens", "lastInputTokens", "estimator");
      if (!usage.keySet().containsAll(requiredKeys) || !requiredKeys.containsAll(usage.keySet())) return;
      for (String key : List.of("modelCalls", "providerReportedCalls", "estimatedCalls", "cacheReportedCalls")) {
        if (!validUsageInteger(usage.get(key), 10_000)) return;
      }
      for (String key : List.of("inputTokens", "outputTokens", "totalTokens", "cachedInputTokens", "cacheWriteTokens",
          "reasoningTokens", "estimatedInputTokens", "contextWindowTokens", "contextWindowUsedTokens", "peakInputTokens", "lastInputTokens")) {
        if (!validUsageInteger(usage.get(key), 4_000_000_000L)) return;
      }
      for (String key : List.of("contextWindowUsagePermille")) {
        if (!validUsageInteger(usage.get(key), 1000)) return;
      }
      Object incomingCacheRate = usage.get("cacheHitRatePermille");
      if (incomingCacheRate != null && !validUsageInteger(incomingCacheRate, 1000)) return;
      if (!(usage.get("available") instanceof Boolean)
          || !Set.of("PROVIDER", "ESTIMATED", "MIXED", "UNAVAILABLE").contains(usage.get("source"))
          || !Set.of("MODEL", "CONFIGURED", "DEFAULT").contains(usage.get("contextWindowSource"))
          || !validUsageText(usage.get("model"), 120)
          || !validUsageText(usage.get("estimator"), 32)) return;
      for (String key : List.of("modelCalls", "providerReportedCalls", "estimatedCalls", "cacheReportedCalls",
          "inputTokens", "outputTokens", "totalTokens", "cachedInputTokens", "cacheWriteTokens",
          "reasoningTokens", "estimatedInputTokens")) {
        long oldValue = number(aggregate.get(key));
        long delta = number(usage.get(key));
        aggregate.put(key, Math.min(4_000_000_000L, oldValue + delta));
      }
      long modelCalls = number(aggregate.get("modelCalls"));
      aggregate.put("available", modelCalls > 0);
      long providerCalls = number(aggregate.get("providerReportedCalls"));
      long estimatedCalls = number(aggregate.get("estimatedCalls"));
      String aggregateSource;
      if (providerCalls > 0 && estimatedCalls > 0) {
        aggregateSource = "MIXED";
      } else if (providerCalls > 0) {
        aggregateSource = "PROVIDER";
      } else if (estimatedCalls > 0) {
        aggregateSource = "ESTIMATED";
      } else {
        aggregateSource = "UNAVAILABLE";
      }
      aggregate.put("source", aggregateSource);
      aggregate.put("model", usage.getOrDefault("model", ""));
      long window = Math.max(1L, number(usage.getOrDefault("contextWindowTokens", 128_000)));
      aggregate.put("contextWindowTokens", (int) Math.min(4_000_000L, window));
      aggregate.put("contextWindowSource", usage.getOrDefault("contextWindowSource", "DEFAULT"));
      long windowUsed = Math.max(number(aggregate.get("contextWindowUsedTokens")), number(usage.get("contextWindowUsedTokens")));
      aggregate.put("contextWindowUsedTokens", windowUsed);
      long usagePermille = Math.min(1000L, Math.max(0L, Math.round((double) windowUsed * 1000.0 / window)));
      aggregate.put("contextWindowUsagePermille", (int) usagePermille);
      aggregate.put("peakInputTokens", Math.max(number(aggregate.get("peakInputTokens")), number(usage.get("peakInputTokens"))));
      aggregate.put("lastInputTokens", usage.getOrDefault("lastInputTokens", 0));
      long cacheReportedCalls = number(aggregate.get("cacheReportedCalls"));
      if (modelCalls > 0 && cacheReportedCalls == modelCalls) {
        long totalInput = number(aggregate.get("inputTokens"));
        long totalCached = number(aggregate.get("cachedInputTokens"));
        int rate = totalInput <= 0 ? 0 : (int) Math.min(1000L, Math.max(0L, Math.round((double) totalCached * 1000.0 / totalInput)));
        aggregate.put("cacheHitRatePermille", rate);
      } else {
        aggregate.put("cacheHitRatePermille", null);
      }
      aggregate.put("estimator", usage.getOrDefault("estimator", "heuristic-v1"));
      session.usage = java.util.Collections.unmodifiableMap(new LinkedHashMap<>(aggregate));
      session.lastAccess = Instant.now();
      try {
        persist(sessionId, session);
      } catch (RuntimeException ex) {
        session.usage = previousUsage;
        session.lastAccess = previousLastAccess;
        throw ex;
      }
    }
  }

  private long number(Object value) {
    return value instanceof Number number ? Math.max(0, number.longValue()) : 0;
  }

  private Map<String, Object> parseUsage(String json) {
    if (json == null || json.isBlank() || json.length() > 16_384) return new LinkedHashMap<>();
    try {
      Map<String, Object> value = objectMapper.readValue(json, new TypeReference<Map<String, Object>>() {});
      Set<String> allowed = Set.of("available", "source", "model", "modelCalls", "providerReportedCalls",
          "estimatedCalls", "cacheReportedCalls", "inputTokens", "outputTokens", "totalTokens",
          "cachedInputTokens", "cacheWriteTokens", "reasoningTokens", "estimatedInputTokens",
          "cacheHitRatePermille", "contextWindowTokens", "contextWindowSource", "contextWindowUsedTokens",
          "contextWindowUsagePermille", "peakInputTokens", "lastInputTokens", "estimator");
      if (value.size() != allowed.size() || !allowed.containsAll(value.keySet())) return new LinkedHashMap<>();
      if (!(value.get("available") instanceof Boolean)
          || !Set.of("PROVIDER", "ESTIMATED", "MIXED", "UNAVAILABLE").contains(value.get("source"))
          || !Set.of("MODEL", "CONFIGURED", "DEFAULT").contains(value.get("contextWindowSource"))
          || !validUsageText(value.get("model"), 120)
          || !validUsageText(value.get("estimator"), 32)) return new LinkedHashMap<>();
      for (String key : List.of("modelCalls", "providerReportedCalls", "estimatedCalls", "cacheReportedCalls")) {
        if (!validUsageInteger(value.get(key), 10_000)) return new LinkedHashMap<>();
      }
      for (String key : List.of("inputTokens", "outputTokens", "totalTokens", "cachedInputTokens", "cacheWriteTokens",
          "reasoningTokens", "estimatedInputTokens", "contextWindowTokens", "contextWindowUsedTokens", "peakInputTokens", "lastInputTokens")) {
        if (!validUsageInteger(value.get(key), 4_000_000_000L)) return new LinkedHashMap<>();
      }
      if (!validUsageInteger(value.get("contextWindowUsagePermille"), 1000)) return new LinkedHashMap<>();
      Object cacheRate = value.get("cacheHitRatePermille");
      if (cacheRate != null && !validUsageInteger(cacheRate, 1000)) return new LinkedHashMap<>();
      return new LinkedHashMap<>(value);
    } catch (Exception ignored) {
      return new LinkedHashMap<>();
    }
  }

  private boolean validUsageText(Object value, int maxLength) {
    return value instanceof String text && text.length() <= maxLength
        && !text.matches("(?s).*[\\p{Cc}].*");
  }

  private boolean validUsageInteger(Object value, long max) {
    return value instanceof Number number && !(value instanceof Double) && !(value instanceof Float)
        && number.longValue() >= 0 && number.longValue() <= max;
  }

  private String safeText(String value) {
    String clean = value == null ? "" : value.replaceAll("[\\p{Cc}&&[^\\r\\n\\t]]", "").strip();
    return clean.length() <= 4_000 ? clean : clean.substring(0, 4_000);
  }

  public record SessionHandle(String id, Object monitor, Long projectId, Long targetId) {}

  public record SessionScope(Long projectId, Long targetId) {}

  public List<Map<String, Object>> listAllPersistedThreads() {
    if (repository == null) return List.of();
    List<AiConversationSessionRecord> records = repository.findAllByOrderByLastAccessDesc();
    List<Map<String, Object>> threads = new ArrayList<>(records.size());
    for (AiConversationSessionRecord record : records) {
      if (record.getThreadJson() != null && !record.getThreadJson().isBlank()) {
        try {
          @SuppressWarnings("unchecked")
          Map<String, Object> map = objectMapper.readValue(record.getThreadJson(), Map.class);
          threads.add(map);
          continue;
        } catch (Exception ignored) {
        }
      }
      Map<String, Object> fallback = new LinkedHashMap<>();
      fallback.put("id", record.getId());
      fallback.put("title", record.getTitle() != null ? record.getTitle() : "历史对话");
      fallback.put("projectId", record.getProjectId());
      fallback.put("targetId", record.getTargetId());
      fallback.put("targetName", record.getTargetName());
      fallback.put(
          "createdAt",
          record.getCreatedAt() != null
              ? record.getCreatedAt().toString()
              : record.getLastAccess().toString());
      fallback.put("updatedAt", record.getLastAccess().toString());
      fallback.put("messages", List.of());
      threads.add(fallback);
    }
    return threads;
  }

  public synchronized void saveClientThread(String sessionId, Map<String, Object> threadData) {
    if (repository == null || sessionId == null || sessionId.isBlank()) return;
    try {
      AiConversationSessionRecord record =
          repository
              .findById(sessionId)
              .orElseGet(
                  () -> {
                    AiConversationSessionRecord r = new AiConversationSessionRecord();
                    r.setId(sessionId);
                    r.setCreatedAt(Instant.now());
                    r.setTurnsJson("[]");
                    return r;
                  });
      record.setLastAccess(Instant.now());
      if (threadData != null) {
        Object title = threadData.get("title");
        if (title != null) record.setTitle(String.valueOf(title));
        Object proj = threadData.get("projectId");
        if (proj instanceof Number n) record.setProjectId(n.longValue());
        Object tgt = threadData.get("targetId");
        if (tgt instanceof Number n) record.setTargetId(n.longValue());
        Object tgtName = threadData.get("targetName");
        if (tgtName != null) record.setTargetName(String.valueOf(tgtName));
        record.setThreadJson(objectMapper.writeValueAsString(threadData));
      }
      repository.save(record);
    } catch (Exception ignored) {
    }
  }

  public void deletePersistedThread(String sessionId) {
    clear(sessionId);
  }

  public void clearAllPersistedThreads() {
    if (repository != null) {
      repository.deleteAll();
    }
    evictAllLocal();
  }

  private static final class Session {
    private final Long projectId;
    private final Long targetId;
    private final Object monitor = new Object();
    private final ChatMemory memory;
    private final Deque<Turn> turns = new ArrayDeque<>();
    private String lastPlanJson;
    private String summaryJson;
    private Map<String, Object> usage = new LinkedHashMap<>();
    private volatile Instant lastAccess = Instant.now();

    private Session(Long projectId, Long targetId, int maxMessages) {
      this.projectId = projectId;
      this.targetId = targetId;
      this.memory = MessageWindowChatMemory.withMaxMessages(maxMessages);
    }
  }

  private record Turn(boolean user, String text) {}

  private record PersistedTurn(boolean user, String text) {}
}
