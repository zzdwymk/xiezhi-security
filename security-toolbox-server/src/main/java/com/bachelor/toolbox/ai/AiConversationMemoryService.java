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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
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
    synchronized (lifecycleMonitor) {
      evictExpired();
      if (!sessions.containsKey(id)) {
        loadPersisted(id);
      }
      if (!sessions.containsKey(id)) {
        evictAtCapacity();
      }
      session = sessions.computeIfAbsent(id, ignored -> new Session(projectId, targetId, maxMessages));
      synchronized (session.monitor) {
        if (!projectId.equals(session.projectId) || !targetId.equals(session.targetId)) {
          throw new ApiException("AI 会话已绑定其他项目或目标，请新建会话");
        }
        session.lastAccess = Instant.now();
        persist(id, session);
      }
    }
    return new SessionHandle(id, session.monitor, session.projectId, session.targetId);
  }

  public String transcript(String sessionId) {
    Session session = require(sessionId);
    synchronized (session.monitor) {
      ensureCurrent(sessionId, session);
      session.lastAccess = Instant.now();
      StringBuilder output = new StringBuilder();
      for (Turn turn : session.turns) {
        String line = (turn.user ? "用户" : "助手") + "：" + turn.text + "\n";
        if (output.length() + line.length() > MAX_TRANSCRIPT_CHARS) {
          int remaining = MAX_TRANSCRIPT_CHARS - output.length();
          if (remaining > 0) output.append(line, 0, Math.min(remaining, line.length()));
          break;
        }
        output.append(line);
      }
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

  public SessionScope clear(String sessionId) {
    if (sessionId == null) return null;
    synchronized (lifecycleMonitor) {
      Session removed = sessions.get(sessionId);
      if (removed != null) {
        synchronized (removed.monitor) {
          sessions.remove(sessionId, removed);
          removed.memory.clear();
          removed.turns.clear();
          deletePersisted(sessionId);
          clearRuntimeMemory(removed.projectId, sessionId);
        }
        return new SessionScope(removed.projectId, removed.targetId);
      }
      AiConversationSessionRecord persisted =
          repository == null ? null : repository.findById(sessionId).orElse(null);
      if (persisted != null) {
        repository.delete(persisted);
        clearRuntimeMemory(persisted.getProjectId(), sessionId);
        return new SessionScope(persisted.getProjectId(), persisted.getTargetId());
      }
      return null;
    }
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

  private void evictExpired() {
    Instant threshold = Instant.now().minus(ttl);
    for (Map.Entry<String, Session> entry : sessions.entrySet()) {
      String id = entry.getKey();
      Session session = entry.getValue();
      if (!session.lastAccess.isBefore(threshold)) continue;
      synchronized (session.monitor) {
        if (sessions.get(id) != session || !session.lastAccess.isBefore(threshold)) continue;
        if (sessions.remove(id, session)) {
          deletePersisted(id);
          clearRuntimeMemory(session.projectId, id);
        }
      }
    }
    if (repository != null) {
      repository.findByLastAccessBefore(threshold).stream()
          .filter(record -> !sessions.containsKey(record.getId()))
          .forEach(
              record -> {
                repository.delete(record);
                clearRuntimeMemory(record.getProjectId(), record.getId());
              });
    }
  }

  private void evictAtCapacity() {
    if (repository != null) {
      while (repository.count() >= maxSessions) {
        AiConversationSessionRecord oldest =
            repository.findFirstByOrderByLastAccessAsc().orElse(null);
        if (oldest == null) break;
        Session session = sessions.get(oldest.getId());
        if (session == null) {
          repository.delete(oldest);
          clearRuntimeMemory(oldest.getProjectId(), oldest.getId());
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
            clearRuntimeMemory(refreshedOldest.getProjectId(), refreshedOldest.getId());
          }
        }
      }
      return;
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
          clearRuntimeMemory(session.projectId, oldest.getKey());
        }
      }
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

  private void persist(String id, Session session) {
    if (repository == null) return;
    try {
      AiConversationSessionRecord record = new AiConversationSessionRecord();
      record.setId(id);
      record.setProjectId(session.projectId);
      record.setTargetId(session.targetId);
      record.setLastAccess(session.lastAccess);
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

  private String safeText(String value) {
    String clean = value == null ? "" : value.replaceAll("[\\p{Cc}&&[^\\r\\n\\t]]", "").strip();
    return clean.length() <= 4_000 ? clean : clean.substring(0, 4_000);
  }

  public record SessionHandle(String id, Object monitor, Long projectId, Long targetId) {}

  public record SessionScope(Long projectId, Long targetId) {}

  private static final class Session {
    private final Long projectId;
    private final Long targetId;
    private final Object monitor = new Object();
    private final ChatMemory memory;
    private final Deque<Turn> turns = new ArrayDeque<>();
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
