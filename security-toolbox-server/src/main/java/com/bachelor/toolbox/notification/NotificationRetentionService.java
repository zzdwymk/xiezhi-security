package com.bachelor.toolbox.notification;

import java.time.Duration;
import java.time.Instant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

/**
 * 第347轮：通知保留策略。
 *
 * <p>{@code SystemNotification} 只增不减：长期运行后表会持续膨胀，备份与查询成本上升。本服务按
 * {@code toolbox.notification.retention-days}（默认 90 天）清理历史通知，默认每天 03:30 执行。
 */
@Service
public class NotificationRetentionService {
  private static final Logger log = LoggerFactory.getLogger(NotificationRetentionService.class);
  private static final int BATCH_SIZE = 500;
  private static final int MAX_BATCHES = 200;

  private final NotificationRepository repository;
  private final int retentionDays;

  public NotificationRetentionService(
      NotificationRepository repository,
      @Value("${toolbox.notification.retention-days:90}") int retentionDays) {
    this.repository = repository;
    this.retentionDays = Math.max(1, retentionDays);
  }

  @Scheduled(cron = "${toolbox.notification.cleanup-cron:0 30 3 * * *}")
  public void scheduledPurge() {
    purgeExpired(Instant.now());
  }

  /** 返回删除条数；供测试注入固定时间。 */
  int purgeExpired(Instant now) {
    Instant cutoff = now.minus(Duration.ofDays(retentionDays));
    int total = 0;
    // Round 348：分批删除（每批 500 条，最多 200 批），避免一次大事务长时间锁表。
    for (int batch = 0; batch < MAX_BATCHES; batch++) {
      java.util.List<Long> ids =
          repository.findIdsByCreatedAtBefore(
              cutoff, org.springframework.data.domain.PageRequest.of(0, BATCH_SIZE));
      if (ids.isEmpty()) break;
      repository.deleteAllByIdInBatch(ids);
      total += ids.size();
    }
    if (total > 0) {
      log.info("通知保留清理：删除 {} 条早于 {} 的通知", total, cutoff);
    }
    return total;
  }

  int retentionDays() {
    return retentionDays;
  }
}
