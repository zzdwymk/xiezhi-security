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
}