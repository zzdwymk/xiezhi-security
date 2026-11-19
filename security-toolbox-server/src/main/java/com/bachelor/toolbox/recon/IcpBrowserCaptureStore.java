package com.bachelor.toolbox.recon;

import java.time.Clock;
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
  private static final int MAX_ENTRIES = 500;

  private final ConcurrentHashMap<String, Entry> store = new ConcurrentHashMap<>();
  private final Clock clock;

  public IcpBrowserCaptureStore() { this(Clock.systemUTC()); }
  IcpBrowserCaptureStore(Clock clock) { this.clock = java.util.Objects.requireNonNull(clock); }

  public synchronized void store(Long projectId, Long targetId, String domain,
      List<Map<String, Object>> records) {
    validatePayload(domain, records);
    purge();
    // Controller records contain canonical scalar fields. Snapshot both collection
    // levels so neither the importer nor a later reader can rewrite saved results.
    List<Map<String, Object>> snapshot = records == null ? List.of() : records.stream()
        .map(row -> java.util.Collections.unmodifiableMap(new java.util.LinkedHashMap<>(row)))
        .toList();
    String captureKey = key(projectId, targetId);
    // Expired entries have already been purged. Evict only for a new key;
    // replacing an existing capture must not discard another project's record.
    if (!store.containsKey(captureKey) && store.size() >= MAX_ENTRIES) {
      store.entrySet().stream().min(java.util.Comparator.comparing(e -> e.getValue().expiresAt()))
          .ifPresent(oldest -> store.remove(oldest.getKey()));
    }
    store.put(captureKey, new Entry(domain, snapshot, clock.instant().plus(TTL)));
  }

  public synchronized Capture take(Long projectId, Long targetId) {
    purge();
    if (projectId == null || targetId == null) {
      return null;
    }
    Entry entry = store.get(key(projectId, targetId));
    if (entry == null) return null;
    // Time may cross the deadline after purge, even while the store lock is held.
    if (!entry.expiresAt().isAfter(clock.instant())) {
      store.remove(key(projectId, targetId), entry);
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

  private static void validatePayload(String domain, List<Map<String, Object>> records) {
    if (domain != null && domain.length() > 253) throw new com.bachelor.toolbox.common.ApiException("捕获域名长度超过限制");
    if (records == null) return;
    if (records.size() > 500) throw new com.bachelor.toolbox.common.ApiException("一次捕获最多保存 500 条记录");
    long characters = domain == null ? 0 : domain.length();
    for (Map<String, Object> row : records) {
      if (row == null || row.size() > 16) throw new com.bachelor.toolbox.common.ApiException("捕获记录字段数量无效");
      for (var field : row.entrySet()) {
        if (field.getKey() == null || field.getKey().length() > 64)
          throw new com.bachelor.toolbox.common.ApiException("捕获记录字段名无效");
        Object value = field.getValue();
        if (value != null && !(value instanceof String))
          throw new com.bachelor.toolbox.common.ApiException("捕获记录字段仅允许文本");
        String text = value == null ? "" : (String) value;
        if (text.length() > 2048) throw new com.bachelor.toolbox.common.ApiException("捕获记录单字段超过 2048 字符限制");
        characters += field.getKey().length() + text.length();
        if (characters > 100_000) throw new com.bachelor.toolbox.common.ApiException("捕获记录总文本超过 100000 字符限制");
      }
    }
  }

  private void purge() {
    Instant now = clock.instant();
    store.entrySet().removeIf(e -> !e.getValue().expiresAt().isAfter(now));
  }

  private String key(Long projectId, Long targetId) {
    return projectId + ":" + targetId;
  }

  public record Capture(String domain, List<Map<String, Object>> records) {}

  private record Entry(String domain, List<Map<String, Object>> records, Instant expiresAt) {}
}