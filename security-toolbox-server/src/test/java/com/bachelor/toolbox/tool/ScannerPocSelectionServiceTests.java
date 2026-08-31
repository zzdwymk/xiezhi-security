package com.bachelor.toolbox.tool;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
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
            root.resolve("xray-pocs").toString(),
            root.resolve("host-plugins").toString());

    List<ScannerPocSelectionService.SelectedPoc> selected =
        service.resolve(
            ScannerPocCatalogService.AFROG, Map.of("allPocs", true), false);

    assertThat(selected)
        .singleElement()
        .extracting(ScannerPocSelectionService.SelectedPoc::externalId)
        .isEqualTo("example");
    verify(repository, never()).findAllByVulnerabilityCodeIn(anyList());
  }

  @Test
  void scheduledSafeOnlySelectionRejectsReviewRequiredPoc() throws Exception {
    Path xray = root.resolve("xray-pocs");
    Files.createDirectories(xray);
    byte[] content = "name: review-required".getBytes(StandardCharsets.UTF_8);
    Files.write(xray.resolve("review.yml"), content);
    VulnerabilityDefinition item =
        poc(
            "XR-1234567890ABCDEF12345678",
            ScannerPocCatalogService.XRAY,
            "review.yml",
            "REVIEW_REQUIRED",
            content);
    VulnerabilityDefinitionRepository repository = mock(VulnerabilityDefinitionRepository.class);
    when(repository.findAllByVulnerabilityCodeIn(List.of(item.getVulnerabilityCode())))
        .thenReturn(List.of(item));
    ScannerPocSelectionService service = service(repository, xray);

    assertThatThrownBy(
            () ->
                service.resolve(
                    ScannerPocCatalogService.XRAY,
                    Map.of(
                        "pocCodes",
                        List.of(item.getVulnerabilityCode()),
                        ScannerPocSelectionService.SAFE_ONLY_PARAMETER,
                        true),
                    false))
        .hasMessage("定时扫描仅允许执行标记为 SAFE 的 PoC: " + item.getVulnerabilityCode());
  }

  @Test
  void scheduledSafeOnlySelectionAcceptsSafePocAndRechecksItsFile() throws Exception {
    Path xray = root.resolve("xray-pocs");
    Files.createDirectories(xray);
    byte[] content = "name: safe".getBytes(StandardCharsets.UTF_8);
    Files.write(xray.resolve("safe.yml"), content);
    VulnerabilityDefinition item =
        poc(
            "XR-ABCDEF1234567890ABCDEF12",
            ScannerPocCatalogService.XRAY,
            "safe.yml",
            "SAFE",
            content);
    VulnerabilityDefinitionRepository repository = mock(VulnerabilityDefinitionRepository.class);
    when(repository.findAllByVulnerabilityCodeIn(List.of(item.getVulnerabilityCode())))
        .thenReturn(List.of(item));
    ScannerPocSelectionService service = service(repository, xray);

    List<ScannerPocSelectionService.SelectedPoc> selected =
        service.resolve(
            ScannerPocCatalogService.XRAY,
            Map.of(
                "pocCodes",
                List.of(item.getVulnerabilityCode()),
                ScannerPocSelectionService.SAFE_ONLY_PARAMETER,
                true),
            false);

    assertThat(selected)
        .singleElement()
        .extracting(ScannerPocSelectionService.SelectedPoc::vulnerabilityCode)
        .isEqualTo(item.getVulnerabilityCode());
  }

  private ScannerPocSelectionService service(
      VulnerabilityDefinitionRepository repository, Path xray) {
    return new ScannerPocSelectionService(
        repository,
        new ObjectMapper(),
        root.resolve("nuclei-templates").toString(),
        root.resolve("afrog-pocs").toString(),
        xray.toString(),
        root.resolve("host-plugins").toString());
  }

  private VulnerabilityDefinition poc(
      String code, String source, String relativePath, String scanSafety, byte[] content)
      throws Exception {
    VulnerabilityDefinition item = new VulnerabilityDefinition();
    item.setVulnerabilityCode(code);
    item.setSourceExternalId(relativePath);
    item.setSourceType(source);
    item.setName(relativePath);
    item.setSeverity("MEDIUM");
    item.setScanSafety(scanSafety);
    item.setTemplateRelativePath(relativePath);
    item.setTemplateSha256(
        HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(content)));
    item.setSourceActive(true);
    item.setEnabled(true);
    return item;
  }
}
