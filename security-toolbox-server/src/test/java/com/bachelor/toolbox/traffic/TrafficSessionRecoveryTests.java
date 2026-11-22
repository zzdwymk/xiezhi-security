package com.bachelor.toolbox.traffic;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

/**
 * 第299轮：进程异常退出后残留在库里的 RUNNING/STARTING 流量会话必须被自愈清理。
 *
 * <p>崩溃（或强制结束）时 {@code stop()} 不会执行，会话行永远停在 RUNNING。此后：
 * {@code TrafficProxyService.status().running()} 为 false（内存里没有代理），但
 * {@code BusinessDataResetService.assertIdle()} 依据 {@code countByStatusIn} 判断"流量代理仍在运行"，
 * 于是「清空业务数据」被永久拒绝，用户无任何手段恢复。
 */
@SpringBootTest(
    properties = {
      "spring.datasource.url=jdbc:h2:mem:traffic-session-recovery;MODE=PostgreSQL;DB_CLOSE_DELAY=-1",
      "spring.jpa.hibernate.ddl-auto=create-drop",
      "toolbox.auth.allow-insecure-development-credentials=true",
      "toolbox.traffic.mitm-enabled=false",
      "toolbox.vulnerability-catalog.nuclei.import-on-startup=false",
      "toolbox.vulnerability-catalog.cisa-kev-enabled=false"
    })
class TrafficSessionRecoveryTests {
  @Autowired TrafficProxyService proxy;
  @Autowired TrafficSessionRepository sessions;

  @Test
  void statusHealsSessionsLeftRunningByACrashedProcess() {
    TrafficSession stale = new TrafficSession();
    stale.setName("崩溃残留会话");
    stale.setTargetId(0L);
    stale.setListenPort(19080);
    stale.setHandlingMode("ASK");
    stale.setStatus("RUNNING");
    stale.setStartedAt(Instant.now().minusSeconds(600));
    stale = sessions.saveAndFlush(stale);

    TrafficProxyService.Status status = proxy.status();

    assertThat(status.running()).as("内存中没有代理，状态必须报告未运行").isFalse();
    assertThat(sessions.findById(stale.getId()).orElseThrow().getStatus())
        .as("残留的 RUNNING 会话必须被自愈为 FAILED，否则「清空业务数据」会被永久拒绝")
        .isEqualTo("FAILED");
    assertThat(sessions.countByStatusIn(java.util.List.of("STARTING", "RUNNING"))).isZero();
  }
}
