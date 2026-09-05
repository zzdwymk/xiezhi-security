package com.bachelor.toolbox.msf;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.vulnerability.CatalogSyncProgress;
import com.bachelor.toolbox.vulnerability.ScannerPocCatalogSyncResult;
import com.bachelor.toolbox.vulnerability.VulnerabilityDefinition;
import com.bachelor.toolbox.vulnerability.VulnerabilityDefinitionRepository;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;

class MsfModuleCatalogServiceTests {
  private final VulnerabilityDefinitionRepository repository =
      mock(VulnerabilityDefinitionRepository.class);

  private MsfModuleCatalogService service() {
    MsfModuleEnumerator enumerator = mock(MsfModuleEnumerator.class);
    when(enumerator.enumerate())
        .thenReturn(
            List.of(
                new MsfModuleOutputParser.MsfLine(
                    "auxiliary",
                    "auxiliary/scanner/ssh/ssh_login",
                    "SSH Login",
                    "normal",
                    "Checks"),
                new MsfModuleOutputParser.MsfLine(
                    "exploit",
                    "exploit/multi/script/web_delivery",
                    "Web Delivery",
                    "great",
                    "Serves")));
    return new MsfModuleCatalogService(enumerator, repository, false);
  }

  @Test
  void syncImportsNewModulesIntoRepository() throws Exception {
    when(repository.findAllBySourceType("MSF")).thenReturn(List.of());
    MsfModuleCatalogService service = service();

    ScannerPocCatalogSyncResult result = service.sync();

    assertThat(result.status()).isEqualTo("SUCCESS");
    assertThat(result.discovered()).isEqualTo(2);
    assertThat(result.imported()).isEqualTo(2);
    assertThat(result.updated()).isZero();
    verify(repository).saveAll(org.mockito.ArgumentMatchers.anyList());
  }

  @Test
  void syncMarksExistingModuleUnchangedAndDeactivatesStaleModule() throws Exception {
    VulnerabilityDefinition existing = new VulnerabilityDefinition();
    existing.setId(1L);
    existing.setSourceType("MSF");
    existing.setSourceExternalId("auxiliary/scanner/ssh/ssh_login");
    existing.setSourceActive(true);
    existing.setName("SSH Login");
    existing.setSeverity("INFO");
    existing.setCategory("MSF 辅助探测");
    existing.setTemplateRelativePath("auxiliary/scanner/ssh/ssh_login");
    existing.setVulnerabilityCode(MsfModuleCatalogService.stableCodeFor("auxiliary/scanner/ssh/ssh_login"));

    VulnerabilityDefinition stale = new VulnerabilityDefinition();
    stale.setId(2L);
    stale.setSourceType("MSF");
    stale.setSourceExternalId("auxiliary/scanner/ftp/anonymous");
    stale.setSourceActive(true);
    stale.setName("ftp anon");
    stale.setSeverity("INFO");
    stale.setCategory("辅助");
    stale.setTemplateRelativePath("auxiliary/scanner/ftp/anonymous");
    stale.setVulnerabilityCode(MsfModuleCatalogService.stableCodeFor("auxiliary/scanner/ftp/anonymous"));

    when(repository.findAllBySourceType("MSF")).thenReturn(List.of(existing, stale));

    MsfModuleCatalogService service = service();
    ScannerPocCatalogSyncResult result = service.sync();

    assertThat(result.imported()).isEqualTo(1);
    assertThat(result.unchanged()).isEqualTo(1);
    assertThat(result.deactivated()).isEqualTo(1);
    assertThat(existing.getSourceActive()).isTrue();
    assertThat(stale.getSourceActive()).isFalse();
  }

  @Test
  void syncReportsToolUnavailableWhenEnumeratorThrows() {
    MsfModuleEnumerator enumerator = mock(MsfModuleEnumerator.class);
    when(enumerator.enumerate())
        .thenThrow(new ApiException("未检测到 MetasploitFramework，无法同步 MSF 模块库"));
    MsfModuleCatalogService service = new MsfModuleCatalogService(enumerator, repository, false);

    assertThatThrownBy(service::sync)
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("MetasploitFramework");
    assertThat(service.isSyncing()).isFalse();
  }
}