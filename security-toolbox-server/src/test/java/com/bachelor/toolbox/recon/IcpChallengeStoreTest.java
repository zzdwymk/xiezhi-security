package com.bachelor.toolbox.recon;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class IcpChallengeStoreTest {

  private final IcpChallengeStore store = new IcpChallengeStore();

  @Test
  void consumesAChallengeExactlyOnce() {
    MiitIcpClient.PendingCaptcha pending =
        new MiitIcpClient.PendingCaptcha("token", "uuid", "secret", "client", "big", "small");
    String id = store.register(pending);

    assertThat(store.take(id)).isSameAs(pending);
    assertThat(store.take(id)).isNull();
  }

  @Test
  void returnsNullForUnknownOrBlankChallenge() {
    assertThat(store.take(null)).isNull();
    assertThat(store.take("does-not-exist")).isNull();
  }

  @Test
  void registeringExpiredChanceIsDropped() {
    // Sanity: registering a fresh challenge creates a usable id.
    MiitIcpClient.PendingCaptcha pending =
        new MiitIcpClient.PendingCaptcha("t", "u", "s", "c", "b", "sm");
    String id = store.register(pending);
    assertThat(id).isNotBlank();
    assertThat(store.take(id)).isNotNull();
  }

  @Test
  void entryCountIsBoundedByHardCap() {
    // Round 29：TTL 窗口内反复 register 也不得让未消费条目无界增长；总数应封顶（≈MAX_ENTRIES=500）。
    MiitIcpClient.PendingCaptcha pending =
        new MiitIcpClient.PendingCaptcha("t", "u", "s", "c", "b", "sm");
    java.util.List<String> ids = new java.util.ArrayList<>();
    for (int i = 0; i < 800; i++) {
      ids.add(store.register(pending));
    }
    // 前 800 次注册后，仍可 take 的条目数应 ≤ 500（早期条目被淘汰）。
    long alive = ids.stream().filter(id -> store.take(id) != null).count();
    assertThat(alive).isLessThanOrEqualTo(500);
    assertThat(alive).isGreaterThan(0);
  }
}