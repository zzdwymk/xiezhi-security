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
    long deleted = repository.deleteByCreatedAtBefore(cutoff);
    if (deleted > 0) {
      log.info("通知保留清理：删除 {} 条早于 {} 的通知", deleted, cutoff);
    }
    return (int) Math.min(Integer.MAX_VALUE, deleted);
  }

  int retentionDays() {
    return retentionDays;
  }
}
