package com.bachelor.toolbox.recon;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Component;

/**
 * Short-lived in-memory store for manual MIIT point-challenge sessions. A pending challenge holds
 * the opaque auth token, the secret key and the client uid on the server side so they are never
 * exposed to the browser; only the operator's clicked coordinates are submitted back later.
 */
@Component
public class IcpChallengeStore {

  private static final Duration TTL = Duration.ofMinutes(10);

  private final ConcurrentHashMap<String, Entry> store = new ConcurrentHashMap<>();

  public synchronized String register(MiitIcpClient.PendingCaptcha pending) {
    purge();
    String id = UUID.randomUUID().toString();
    store.put(id, new Entry(pending, Instant.now().plus(TTL)));
    return id;
  }

  /**
   * Removes and returns the pending challenge for the given id, or {@code null} if it is unknown
   * or has expired. A challenge can be consumed only once.
   */
  public MiitIcpClient.PendingCaptcha take(String challengeId) {
    if (challengeId == null) {
      return null;
    }
    purge();
    Entry entry = store.remove(challengeId);
    return entry == null ? null : entry.pending();
  }

  private void purge() {
    Instant now = Instant.now();
    store.entrySet().removeIf(e -> e.getValue().expiresAt().isBefore(now));
  }

  private record Entry(MiitIcpClient.PendingCaptcha pending, Instant expiresAt) {}
}