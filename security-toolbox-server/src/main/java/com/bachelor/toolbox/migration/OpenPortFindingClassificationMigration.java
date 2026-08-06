package com.bachelor.toolbox.migration;

import com.bachelor.toolbox.finding.FindingRepository;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/** Removes legacy rows that incorrectly treated a reachable port as a vulnerability. */
@Component
public class OpenPortFindingClassificationMigration implements ApplicationRunner {
  private static final Logger log =
      LoggerFactory.getLogger(OpenPortFindingClassificationMigration.class);
  private final FindingRepository findings;

  public OpenPortFindingClassificationMigration(FindingRepository findings) {
    this.findings = findings;
  }

  @Override
  @Transactional
  public void run(ApplicationArguments args) {
    long removed =
        findings.deleteBySourceToolInAndTitleStartingWithAndVulnerabilityCodeIsNull(
            List.of("tcp_ports", "nmap_service_scan"), "发现开放 TCP 端口 ");
    if (removed > 0) {
      log.info(
          "Reclassified legacy open-port observations: removed {} rows from vulnerability findings",
          removed);
    }
  }
}
