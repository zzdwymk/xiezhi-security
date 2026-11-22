package com.bachelor.toolbox.settings;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

import com.bachelor.toolbox.task.SecurityTask;
import com.bachelor.toolbox.task.SecurityTaskRepository;
import java.time.Instant;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

/**
 * 第300轮：崩溃残留的 RUNNING 任务不得永久阻塞「清空业务数据」。
 *
 * <p>与 R299 的流量会话同源：进程被强制结束时任务行停在 RUNNING/PENDING，但内存里没有对应 worker。
 * {@code assertIdle()} 只按数据库状态计数，会把这类"僵尸任务"当成正在执行，导致清空数据被永久拒绝。
 * 正确做法是区分「有活跃 worker」与「无 worker 的残留行」，后者自愈为 FAILED。
 */
@SpringBootTest(
    properties = {
      "spring.datasource.url=jdbc:h2:mem:business-reset-stale-task;MODE=PostgreSQL;DB_CLOSE_DELAY=-1",
      "spring.jpa.hibernate.ddl-auto=create-drop",
      "toolbox.auth.allow-insecure-development-credentials=true",
      "toolbox.traffic.mitm-enabled=false",
      "toolbox.vulnerability-catalog.nuclei.import-on-startup=false",
      "toolbox.vulnerability-catalog.cisa-kev-enabled=false"
    })
class BusinessResetStaleTaskTests {
  @Autowired BusinessDataResetService reset;
  @Autowired SecurityTaskRepository tasks;

  @Test
  void staleRunningTaskDoesNotBlockResetAndIsHealed() {
    SecurityTask stale = new SecurityTask();
    stale.setProjectId(1L);
    stale.setTargetId(1L);
    stale.setToolCode("http_headers");
    stale.setStatus("RUNNING");
    stale.setProgress(37);
    stale.setCreatedAt(Instant.now().minusSeconds(3600));
    stale.setStartedAt(Instant.now().minusSeconds(3500));
    stale = tasks.saveAndFlush(stale);

    SecurityTask saved = stale;
    assertThatCode(reset::assertIdle)
        .as("没有活跃 worker 的 RUNNING 行是崩溃残留，不得阻塞清空数据")
        .doesNotThrowAnyException();

    assertThat(tasks.findById(saved.getId()).orElseThrow().getStatus())
        .as("残留任务必须被自愈为 FAILED，否则页面永远显示执行中")
        .isEqualTo("FAILED");
  }
}
