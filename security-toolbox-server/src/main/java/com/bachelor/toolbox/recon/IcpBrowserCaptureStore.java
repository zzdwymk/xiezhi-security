package com.bachelor.toolbox.recon;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Component;

/**
 * In-memory store of ICP records that an operator captured from the live MIIT page in the desktop
 * browser assistant and asked to import. Keyed by {@code projectId:targetId} so a later ICP batch
 * query merges the human-verified rows back into the result table until the project store is
 * cleared / the entry expires. Nothing here is executed against the target; it only records rows the
 * operator chose to import.
 */
@Component
public class IcpBrowserCaptureStore {

  private static final Duration TTL = Duration.ofHours(24);

  private final ConcurrentHashMap<String, Entry> store = new ConcurrentHashMap<>();

  public synchronized void store(Long projectId, Long targetId, String domain,
      List<Map<String, Object>> records) {
    purge();
    store.put(key(projectId, targetId),
        new Entry(domain, records, Instant.now().plus(TTL)));
  }

  public synchronized Capture take(Long projectId, Long targetId) {
    purge();
    if (projectId == null || targetId == null) {
      return null;
    }
    Entry entry = store.get(key(projectId, targetId));
    if (entry == null) {
      return null;
    }
    // A capture remains available until the store is explicitly cleared (mirrors an imported
    // result that stays in the surface until the user resets the catalog).
    return new Capture(entry.domain(), entry.records());
  }

  public synchronized void clear(Long projectId, Long targetId) {
    if (projectId == null || targetId == null) {
      return;
    }
    store.remove(key(projectId, targetId));
  }

  private void purge() {
    Instant now = Instant.now();
    store.entrySet().removeIf(e -> e.getValue().expiresAt().isBefore(now));
  }

  private String key(Long projectId, Long targetId) {
    return projectId + ":" + targetId;
  }

  public record Capture(String domain, List<Map<String, Object>> records) {}

  private record Entry(String domain, List<Map<String, Object>> records, Instant expiresAt) {}
}