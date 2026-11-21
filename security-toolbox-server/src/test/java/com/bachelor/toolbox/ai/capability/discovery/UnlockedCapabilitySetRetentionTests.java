package com.bachelor.toolbox.ai.capability.discovery;

import static org.assertj.core.api.Assertions.assertThat;

import com.bachelor.toolbox.ai.capability.AgentCapability;
import com.bachelor.toolbox.ai.capability.CapabilityRegistry;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

/**
 * 第290轮：AI 会话的解锁桶必须随会话数量有上界，不能在长跑进程里无界增长。
 *
 * <p>触发路径：用户每开一个 AI 会话并解锁能力，就新建一个桶；{@code clearSession} 只清对话记忆，
 * 从不清理这些桶，因此桶数与会话数同阶增长。
 */
@SpringBootTest(
    properties = {
      "spring.datasource.url=jdbc:h2:mem:unlock-set-290;MODE=PostgreSQL;DB_CLOSE_DELAY=-1",
      "spring.jpa.hibernate.ddl-auto=create-drop",
      "toolbox.auth.admin-password=test-admin-password-7bbbe095d8724fcb",
      "toolbox.auth.jwt-secret=test-jwt-secret-cdc24d415ad843aa9ef313028ae9be30",
      "toolbox.traffic.mitm-enabled=false",
      "toolbox.vulnerability-catalog.nuclei.import-on-startup=false",
      "toolbox.vulnerability-catalog.cisa-kev-enabled=false"
    })
class UnlockedCapabilitySetRetentionTests {
  @Autowired private UnlockedCapabilitySet unlockSet;
  @Autowired private CapabilityRegistry registry;

  @Test
  void sessionBucketsStayBoundedWhenManySessionsUnlockCapabilities() {
    String unlockable =
        registry.all().stream()
            .filter(CapabilityLayers::isUnlockable)
            .map(AgentCapability::code)
            .findFirst()
            .orElse(null);
    Assumptions.assumeTrue(unlockable != null, "上下文中没有可解锁能力，跳过");

    for (int i = 0; i < UnlockedCapabilitySet.MAX_SESSIONS + 200; i++) {
      unlockSet.unlock("retention-session-" + i, unlockable);
    }

    assertThat(unlockSet.sessionCount())
        .as("会话桶数量必须有上界，否则内存随会话数无界增长")
        .isLessThanOrEqualTo(UnlockedCapabilitySet.MAX_SESSIONS);

    // 最近使用的会话必须仍然可用
    String newest = "retention-session-" + (UnlockedCapabilitySet.MAX_SESSIONS + 199);
    assertThat(unlockSet.isUnlocked(newest, unlockable)).isTrue();
  }

  @Test
  void clearStillReleasesOneSession() {
    String unlockable =
        registry.all().stream()
            .filter(CapabilityLayers::isUnlockable)
            .map(AgentCapability::code)
            .findFirst()
            .orElse(null);
    Assumptions.assumeTrue(unlockable != null, "上下文中没有可解锁能力，跳过");

    unlockSet.unlock("clear-probe", unlockable);
    assertThat(unlockSet.isUnlocked("clear-probe", unlockable)).isTrue();
    unlockSet.clear("clear-probe");
    assertThat(unlockSet.isUnlocked("clear-probe", unlockable)).isFalse();
  }
}
