package com.bachelor.toolbox.tool;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.vulnerability.ScannerPocCatalogService;
import com.bachelor.toolbox.vulnerability.VulnerabilityDefinition;
import com.bachelor.toolbox.vulnerability.VulnerabilityDefinitionRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ScannerPocSelectionServiceTests {
  @TempDir Path root;

  @Test
  void resolvesAllFromTheTrustedSourceWithoutReceivingEveryCode() throws Exception {
    Path afrog = root.resolve("afrog-pocs");
    Files.createDirectories(afrog);
    byte[] content = "id: example".getBytes(StandardCharsets.UTF_8);
    Files.write(afrog.resolve("example.yaml"), content);
    VulnerabilityDefinition item = new VulnerabilityDefinition();
    item.setVulnerabilityCode("AP-1234567890ABCDEF12345678");
    item.setSourceExternalId("example");
    item.setSourceType(ScannerPocCatalogService.AFROG);
    item.setName("Example PoC");
    item.setSeverity("MEDIUM");
    item.setTemplateRelativePath("example.yaml");
    item.setTemplateSha256(
        HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(content)));
    item.setSourceActive(true);
    item.setEnabled(true);
    VulnerabilityDefinitionRepository repository = mock(VulnerabilityDefinitionRepository.class);
    when(repository.findAllBySourceTypeAndEnabledTrueAndSourceActiveTrue(
            ScannerPocCatalogService.AFROG))
        .thenReturn(List.of(item));
    ScannerPocSelectionService service =
        new ScannerPocSelectionService(
            repository,
            new ObjectMapper(),
            root.resolve("nuclei-templates").toString(),
            afrog.toString(),
            root.resolve("xray-pocs").toString());

    List<ScannerPocSelectionService.SelectedPoc> selected =
        service.resolve(
            ScannerPocCatalogService.AFROG, Map.of("allPocs", true), false);

    assertThat(selected)
        .singleElement()
        .extracting(ScannerPocSelectionService.SelectedPoc::externalId)
        .isEqualTo("example");
    verify(repository, never()).findAllByVulnerabilityCodeIn(anyList());
  }
}
