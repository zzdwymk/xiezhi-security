package com.bachelor.toolbox.migration;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import com.bachelor.toolbox.finding.FindingRepository;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.boot.DefaultApplicationArguments;

class OpenPortFindingClassificationMigrationTest {
  @Test
  void removesOnlyLegacyToolGeneratedOpenPortFindings() {
    FindingRepository repository = mock(FindingRepository.class);

    new OpenPortFindingClassificationMigration(repository).run(new DefaultApplicationArguments());

    verify(repository)
        .deleteBySourceToolInAndTitleStartingWithAndVulnerabilityCodeIsNull(
            List.of("tcp_ports", "nmap_service_scan"), "发现开放 TCP 端口 ");
  }
}
