package com.bachelor.toolbox.notification;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

/** 第348轮：通知保留清理必须分批删除，避免一次大事务。 */
class NotificationRetentionServiceTests {

  @Test
  void purgeDeletesInBatchesUsingConfiguredCutoff() {
    NotificationRepository repository = mock(NotificationRepository.class);
    when(repository.findIdsByCreatedAtBefore(any(), any()))
        .thenReturn(List.of(1L, 2L), List.of());
    NotificationRetentionService service = new NotificationRetentionService(repository, 30);

    Instant now = Instant.parse("2026-11-22T00:00:00Z");
    int deleted = service.purgeExpired(now);

    assertThat(deleted).isEqualTo(2);
    verify(repository).deleteAllByIdInBatch(List.of(1L, 2L));
    ArgumentCaptor<Instant> cutoff = ArgumentCaptor.forClass(Instant.class);
    verify(repository, org.mockito.Mockito.atLeastOnce())
        .findIdsByCreatedAtBefore(cutoff.capture(), any());
    assertThat(cutoff.getAllValues().get(0)).isEqualTo(now.minus(Duration.ofDays(30)));
  }

  @Test
  void multipleBatchesAreDeletedUntilEmpty() {
    NotificationRepository repository = mock(NotificationRepository.class);
    when(repository.findIdsByCreatedAtBefore(any(), any()))
        .thenReturn(List.of(1L, 2L), List.of(3L), List.of());
    NotificationRetentionService service = new NotificationRetentionService(repository, 90);

    int deleted = service.purgeExpired(Instant.parse("2026-11-22T00:00:00Z"));

    assertThat(deleted).isEqualTo(3);
    verify(repository, times(3)).findIdsByCreatedAtBefore(any(), any());
    verify(repository).deleteAllByIdInBatch(List.of(1L, 2L));
    verify(repository).deleteAllByIdInBatch(List.of(3L));
  }

  @Test
  void retentionDaysIsClampedToAtLeastOne() {
    assertThat(new NotificationRetentionService(mock(NotificationRepository.class), 0).retentionDays())
        .isEqualTo(1);
    assertThat(new NotificationRetentionService(mock(NotificationRepository.class), -5).retentionDays())
        .isEqualTo(1);
  }
}
