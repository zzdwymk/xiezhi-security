package com.bachelor.toolbox.task;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ConfigurableApplicationContext;

/**
 * 第302轮：启动时必须对账残留任务，否则任务列表永远显示"执行中"。
 *
 * <p>R300 只在「清空数据」入口做对账；任务列表、仪表盘、通知仍会把崩溃残留的 RUNNING 当成执行中。
 * 正确做法是在 {@code ApplicationReadyEvent} 统一对账一次：无活跃 worker 的 RUNNING 行标记为 FAILED。
 */
@SpringBootTest(
    properties = {
      "spring.datasource.url=jdbc:h2:mem:task-startup-reconcile;MODE=PostgreSQL;DB_CLOSE_DELAY=-1",
      "spring.jpa.hibernate.ddl-auto=create-drop",
      "toolbox.auth.allow-insecure-development-credentials=true",
      "toolbox.traffic.mitm-enabled=false",
      "toolbox.vulnerability-catalog.nuclei.import-on-startup=false",
      "toolbox.vulnerability-catalog.cisa-kev-enabled=false"
    })
class TaskStartupReconciliationTests {
  @Autowired SecurityTaskRepository tasks;
  @Autowired ApplicationEventPublisher publisher;
  @Autowired ConfigurableApplicationContext context;
  @Autowired TaskStartupReconciler reconciler;

  @Test
  void reconcilerRunsBeforeOtherStartupListeners() {
    // Round 307：对账必须排在任何"启动期入队"的监听器之前，否则会把刚排入的 PENDING 任务误杀。
    assertThat(reconciler.getOrder())
        .isEqualTo(org.springframework.core.Ordered.HIGHEST_PRECEDENCE);
  }

  @Test
  void applicationReadyMarksInterruptedTasksFailed() {
    SecurityTask stale = new SecurityTask();
    stale.setProjectId(1L);
    stale.setTargetId(1L);
    stale.setToolCode("http_headers");
    stale.setStatus("RUNNING");
    stale.setProgress(55);
    stale.setCreatedAt(Instant.now().minusSeconds(3600));
    stale.setStartedAt(Instant.now().minusSeconds(3500));
    stale = tasks.saveAndFlush(stale);

    publisher.publishEvent(
        new ApplicationReadyEvent(new SpringApplication(), new String[0], context, Duration.ZERO));

    SecurityTask healed = tasks.findById(stale.getId()).orElseThrow();
    assertThat(healed.getStatus())
        .as("启动对账必须把崩溃残留的 RUNNING 任务标记为 FAILED")
        .isEqualTo("FAILED");
    assertThat(healed.getErrorMessage()).contains("服务重启");
    assertThat(tasks.countByStatus("RUNNING")).isZero();
  }
}
