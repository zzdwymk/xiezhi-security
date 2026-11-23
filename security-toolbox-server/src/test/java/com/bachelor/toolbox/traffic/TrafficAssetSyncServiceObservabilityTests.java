package com.bachelor.toolbox.traffic;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.bachelor.toolbox.asset.DiscoveredPathService;
import com.bachelor.toolbox.project.ProjectTarget;
import com.bachelor.toolbox.project.ProjectTargetRepository;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.AuthorizedTargetRepository;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

/**
 * 第362轮：资产同步失败必须可观察。
 *
 * <p>{@code syncTarget} 捕获 RuntimeException 后只记 debug——生产默认 INFO 级别下，资产同步失败
 * 完全不可见，运维无法发现「抓包一直没进资产库」的原因。失败应记 warn（含 target 与 host）。
 */
class TrafficAssetSyncServiceObservabilityTests {

  private final AuthorizedTargetRepository targets = mock(AuthorizedTargetRepository.class);
  private final ProjectTargetRepository projectTargets = mock(ProjectTargetRepository.class);
  private final TrafficPacketRepository packets = mock(TrafficPacketRepository.class);
  private final DiscoveredPathService discoveredPaths = mock(DiscoveredPathService.class);
  private final TrafficAssetSyncService service =
      new TrafficAssetSyncService(targets, projectTargets, packets, discoveredPaths);

  private final ListAppender<ILoggingEvent> appender = new ListAppender<>();
  private final Logger logger = (Logger) LoggerFactory.getLogger(TrafficAssetSyncService.class);
  private Level previousLevel;

  @BeforeEach
  void captureLogs() {
    previousLevel = logger.getLevel();
    logger.setLevel(Level.WARN);
    appender.start();
    logger.addAppender(appender);
  }

  @AfterEach
  void restoreLogs() {
    logger.detachAppender(appender);
    logger.setLevel(previousLevel);
  }

  private AuthorizedTarget target() {
    AuthorizedTarget target = new AuthorizedTarget();
    target.setId(7L);
    target.setTargetValue("http://192.168.222.157/");
    target.setAllowedPorts("80");
    target.setEnabled(true);
    return target;
  }

  @Test
  void syncFailureIsLoggedAtWarnLevelWithTargetContext() {
    when(targets.findAll()).thenReturn(List.of(target()));
    when(projectTargets.findByTargetId(eq(7L))).thenReturn(List.of(new ProjectTarget(1L, 7L)));
    when(packets.findDistinctEndpointsByTargetIdAndHost(eq(7L), any()))
        .thenThrow(new IllegalStateException("db unavailable"));

    int recorded = service.syncAll();

    assertThat(recorded).isZero();
    List<ILoggingEvent> warnings =
        appender.list.stream().filter(event -> event.getLevel() == Level.WARN).toList();
    assertThat(warnings)
        .as("资产同步失败必须以 WARN 级别记录（此前仅 debug，生产不可见）")
        .isNotEmpty();
    assertThat(warnings.get(0).getFormattedMessage())
        .contains("7")
        .contains("192.168.222.157");
  }
}