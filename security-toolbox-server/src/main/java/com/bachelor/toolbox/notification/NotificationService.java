package com.bachelor.toolbox.notification;

import com.bachelor.toolbox.project.ProjectAuthorizationService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;

/** Durable notification feed. Business events become visible only after their transaction commits. */
@Service
public class NotificationService {
  private static final Logger log = LoggerFactory.getLogger(NotificationService.class);
  private static final Set<String> SEVERITIES = Set.of("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO");
  private final NotificationRepository repository;
  private final ProjectAuthorizationService authorization;
  private final com.bachelor.toolbox.finding.FindingRepository findings;
  private final TransactionTemplate writes;
  private final Object publicationLock = new Object();

  @org.springframework.beans.factory.annotation.Autowired
  public NotificationService(NotificationRepository repository,
      ProjectAuthorizationService authorization, PlatformTransactionManager transactions,
      com.bachelor.toolbox.finding.FindingRepository findings) {
    this.repository = repository;
    this.authorization = authorization;
    this.findings = findings;
    writes = new TransactionTemplate(transactions);
    writes.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
  }

  public NotificationService(NotificationRepository repository,
      ProjectAuthorizationService authorization, PlatformTransactionManager transactions) {
    this(repository, authorization, transactions, null);
  }

  /** Read persisted findings, including partial writes made before a task failed. */
  public List<String> findingSeverities(List<Long> taskIds) {
    if (findings == null || taskIds == null || taskIds.isEmpty()) return List.of();
    try {
      return normalizeSeverities(findings.findDistinctSeveritiesByTaskIds(taskIds));
    } catch (RuntimeException exception) {
      log.warn("读取通知漏洞等级失败，taskIds={}", taskIds, exception);
      return List.of();
    }
  }

  public void publish(String eventKey, Long projectId, boolean adminOnly, String category,
      String outcome, String title, String body, String route, List<String> severities) {
    SystemNotification notification = new SystemNotification();
    notification.setEventKey(Objects.requireNonNull(eventKey));
    notification.setProjectId(projectId);
    notification.setAdminOnly(adminOnly);
    notification.setCategory(category);
    notification.setOutcome(outcome);
    notification.setTitle(truncate(title, 180));
    notification.setBody(truncate(body, 2000));
    notification.setRoute(truncate(route, 500));
    notification.setSeverities(String.join(",", normalizeSeverities(severities)));
    Runnable persist = () -> persist(notification);
    if (TransactionSynchronizationManager.isActualTransactionActive()
        && TransactionSynchronizationManager.isSynchronizationActive()) {
      TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
        @Override public void afterCompletion(int status) {
          if (status == STATUS_COMMITTED) persist.run();
        }
      });
    } else {
      persist.run();
    }
  }

  private void persist(SystemNotification notification) {
    // Serialize allocation + commit so a feed cursor cannot skip an uncommitted, smaller ID.
    synchronized (publicationLock) {
      try {
        writes.executeWithoutResult(status -> {
          if (!repository.existsByEventKey(notification.getEventKey())) repository.saveAndFlush(notification);
        });
      } catch (RuntimeException exception) {
        // Notification delivery must never change a successfully committed business operation.
        log.warn("无法保存系统通知，eventKey={}", notification.getEventKey(), exception);
      }
    }
  }

  public Feed feed(Long after, int requestedLimit) {
    boolean admin = authorization.isAdmin();
    String username = authorization.currentUsername();
    int limit = Math.max(1, Math.min(100, requestedLimit));
    synchronized (publicationLock) {
      long boundary = repository.currentCursor();
      if (after == null) return new Feed(List.of(), boundary);
      long start = Math.max(0, Math.min(after, boundary));
      List<SystemNotification> page = repository.findVisibleAfter(
          start, boundary, admin, username, PageRequest.of(0, limit));
      long cursor = page.size() == limit ? page.get(page.size() - 1).getId() : boundary;
      return new Feed(page.stream().map(NotificationService::item).toList(), cursor);
    }
  }

  public static List<String> resultSeverities(ObjectMapper mapper, String resultJson) {
    if (resultJson == null || resultJson.isBlank()) return List.of();
    try {
      JsonNode findings = mapper.readTree(resultJson).path("findings");
      java.util.ArrayList<String> values = new java.util.ArrayList<>();
      findings.forEach(finding -> values.add(finding.path("severity").asText("")));
      return normalizeSeverities(values);
    } catch (Exception ignored) { return List.of(); }
  }

  private static List<String> normalizeSeverities(List<String> values) {
    return values == null ? List.of() : values.stream().filter(Objects::nonNull)
        .map(value -> value.toUpperCase(Locale.ROOT)).filter(SEVERITIES::contains).distinct().sorted().toList();
  }

  private static String truncate(String value, int length) {
    String text = Objects.toString(value, "");
    return text.substring(0, Math.min(length, text.length()));
  }

  private static Item item(SystemNotification value) {
    return new Item(value.getId(), value.getEventKey(), value.getCategory(), value.getOutcome(),
        value.getTitle(), value.getBody(), value.getRoute(),
        value.getSeverities().isBlank() ? List.of() : Arrays.asList(value.getSeverities().split(",")),
        value.getCreatedAt());
  }

  public record Item(Long id, String eventKey, String category, String outcome, String title,
      String body, String route, List<String> severities, Instant createdAt) {}
  public record Feed(List<Item> items, long cursor) {}
}
