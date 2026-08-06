package com.bachelor.toolbox.ai;

import com.bachelor.toolbox.common.ApiException;
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
  private final int maxMessages;
  private final int maxSessions;
  private final Duration ttl;

  public AiConversationMemoryService(
      @Value("${toolbox.ai.agent.memory-messages:20}") int maxMessages,
      @Value("${toolbox.ai.agent.max-sessions:200}") int maxSessions,
      @Value("${toolbox.ai.agent.session-ttl-minutes:120}") long ttlMinutes) {
    this.maxMessages = Math.max(4, Math.min(maxMessages, 100));
    this.maxSessions = Math.max(10, Math.min(maxSessions, 2_000));
    this.ttl = Duration.ofMinutes(Math.max(5, Math.min(ttlMinutes, 24 * 60)));
  }

  public SessionHandle open(String requestedId, Long projectId, Long targetId) {
    if (projectId == null || targetId == null) {
      throw new ApiException("AI 会话必须绑定评估项目和授权目标");
    }
    evictExpired();
    String id =
        requestedId == null || requestedId.isBlank() ? UUID.randomUUID().toString() : requestedId;
    if (!id.matches("[A-Za-z0-9_-]{1,64}")) {
      throw new ApiException("AI 会话编号格式不合法");
    }
    if (!sessions.containsKey(id) && sessions.size() >= maxSessions) {
      sessions.entrySet().stream()
          .min(Comparator.comparing(entry -> entry.getValue().lastAccess))
          .ifPresent(entry -> sessions.remove(entry.getKey(), entry.getValue()));
    }
    Session session =
        sessions.computeIfAbsent(id, ignored -> new Session(projectId, targetId, maxMessages));
    synchronized (session.monitor) {
      if (!projectId.equals(session.projectId) || !targetId.equals(session.targetId)) {
        throw new ApiException("AI 会话已绑定其他项目或目标，请新建会话");
      }
      session.lastAccess = Instant.now();
    }
    return new SessionHandle(id, session.monitor);
  }

  public String transcript(String sessionId) {
    Session session = require(sessionId);
    synchronized (session.monitor) {
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
      return output.toString().strip();
    }
  }

  /** Structured turns for the AI runtime planner (role/content only). */
  public List<Map<String, String>> recentChatMessages(String sessionId) {
    Session session = require(sessionId);
    synchronized (session.monitor) {
      session.lastAccess = Instant.now();
      List<Map<String, String>> out = new ArrayList<>();
      for (Turn turn : session.turns) {
        Map<String, String> item = new LinkedHashMap<>();
        item.put("role", turn.user ? "user" : "assistant");
        item.put("content", turn.text);
        out.add(item);
      }
      return out;
    }
  }

  public void addUser(String sessionId, String text) {
    Session session = require(sessionId);
    synchronized (session.monitor) {
      String safe = safeText(text);
      session.memory.add(UserMessage.from(safe));
      addTurn(session, new Turn(true, safe));
    }
  }

  public void addAssistant(String sessionId, String text) {
    Session session = require(sessionId);
    synchronized (session.monitor) {
      String safe = safeText(text);
      session.memory.add(AiMessage.from(safe));
      addTurn(session, new Turn(false, safe));
    }
  }

  public int messageCount(String sessionId) {
    Session session = require(sessionId);
    synchronized (session.monitor) {
      return session.memory.messages().size();
    }
  }

  public void clear(String sessionId) {
    if (sessionId == null) return;
    Session removed = sessions.remove(sessionId);
    if (removed != null) {
      synchronized (removed.monitor) {
        removed.memory.clear();
        removed.turns.clear();
      }
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

  private void evictExpired() {
    Instant threshold = Instant.now().minus(ttl);
    sessions.entrySet().removeIf(entry -> entry.getValue().lastAccess.isBefore(threshold));
  }

  private String safeText(String value) {
    String clean = value == null ? "" : value.replaceAll("[\\p{Cc}&&[^\\r\\n\\t]]", "").strip();
    return clean.length() <= 4_000 ? clean : clean.substring(0, 4_000);
  }

  public record SessionHandle(String id, Object monitor) {}

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
}
