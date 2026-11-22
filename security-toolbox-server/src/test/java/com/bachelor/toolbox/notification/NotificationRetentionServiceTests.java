package com.bachelor.toolbox.notification;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

/** 第347轮：通知保留策略的截止时间计算。 */
class NotificationRetentionServiceTests {

  @Test
  void purgeUsesConfiguredRetentionDays() {
    NotificationRepository repository = mock(NotificationRepository.class);
    when(repository.deleteByCreatedAtBefore(any())).thenReturn(3L);
    NotificationRetentionService service = new NotificationRetentionService(repository, 30);

    Instant now = Instant.parse("2026-11-22T00:00:00Z");
    int deleted = service.purgeExpired(now);

    ArgumentCaptor<Instant> cutoff = ArgumentCaptor.forClass(Instant.class);
    verify(repository).deleteByCreatedAtBefore(cutoff.capture());
    assertThat(cutoff.getValue()).isEqualTo(now.minus(Duration.ofDays(30)));
    assertThat(deleted).isEqualTo(3);
  }

  @Test
  void retentionDaysIsClampedToAtLeastOne() {
    assertThat(new NotificationRetentionService(mock(NotificationRepository.class), 0).retentionDays())
        .isEqualTo(1);
    assertThat(new NotificationRetentionService(mock(NotificationRepository.class), -5).retentionDays())
        .isEqualTo(1);
  }
}
