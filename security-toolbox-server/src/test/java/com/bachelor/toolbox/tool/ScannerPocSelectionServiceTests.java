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
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class ScannerPocSelectionServiceTests {
  @TempDir Path root;

  @ParameterizedTest
  @ValueSource(strings = {"afrog_scan", "xray_scan", "nuclei_scan"})
  void resolvedWebMetadataDoesNotBreakSnapshotAndPocChangesStillBlockExecution(String toolCode) throws Exception {
    String source = ScannerPocSelectionService.sourceForTool(toolCode);
    byte[] content = "id: snapshot-fixture".getBytes(StandardCharsets.UTF_8);
    Path file = root.resolve("fixture.yaml");
    Files.write(file, content);
    VulnerabilityDefinition item = poc("AP-1234567890ABCDEF12345678", source, "fixture.yaml", "SAFE", content);
    VulnerabilityDefinitionRepository repository = mock(VulnerabilityDefinitionRepository.class);
    when(repository.findAllByVulnerabilityCodeIn(List.of(item.getVulnerabilityCode()))).thenReturn(List.of(item));
    ObjectMapper mapper = new ObjectMapper().findAndRegisterModules();
    ScannerPocSelectionService selection = new ScannerPocSelectionService(
        repository, mapper, root.toString(), root.toString(), root.toString());
    String plain = mapper.writeValueAsString(Map.of("pocCodes", List.of(item.getVulnerabilityCode())));
    String withTarget = mapper.writeValueAsString(Map.of("pocCodes", List.of(item.getVulnerabilityCode()),
        com.bachelor.toolbox.target.WebTargetResolver.PARAM_RESOLVED_BASES, List.of("http://127.0.0.1")));
    String hash = selection.selectionHash(toolCode, plain);
    assertThat(selection.selectionHash(toolCode, withTarget)).isEqualTo(hash);

    var dependencies = mock(com.bachelor.toolbox.dependency.DependencyDetectionService.class);
    when(dependencies.detect()).thenReturn(new com.bachelor.toolbox.dependency.SystemDependenciesResponse(
        "test", "test", "test", List.of()));
    var snapshots = new com.bachelor.toolbox.task.TaskSnapshotService(mapper,
        mock(com.bachelor.toolbox.vulnerability.DetectionRuleRepository.class), dependencies, selection, root.toString());
    var task = new com.bachelor.toolbox.task.SecurityTask();
    task.setToolCode(toolCode);
    task.setRequestJson(withTarget);
    var target = new com.bachelor.toolbox.target.AuthorizedTarget();
    target.setId(1L);
    target.setName("snapshot fixture");
    target.setTargetValue("127.0.0.1");
    target.setTargetType("IP");
    target.setAuthorizationNote("fixture authorization");
    SecurityTool tool = mock(SecurityTool.class);
    when(tool.code()).thenReturn(toolCode);
    snapshots.capture(task, target, tool);
    assertThat(task.getNucleiTemplateHashSnapshot()).isEqualTo(hash);
    assertThat(task.getAuthorizationSnapshotHash()).hasSize(64);
    snapshots.assertCurrentMatches(task, target, tool);
    assertThat(task.getRequestJson()).isEqualTo(withTarget);

    String unknown = mapper.writeValueAsString(Map.of("pocCodes", List.of(item.getVulnerabilityCode()), "unexpected", true));
    assertThatThrownBy(() -> selection.selectionHash(toolCode, unknown)).hasMessageContaining("未允许的参数");
    Files.writeString(file, "id: changed");
    assertThatThrownBy(() -> selection.selectionHash(toolCode, withTarget)).hasMessageContaining("文件已变化");
    assertThatThrownBy(() -> snapshots.assertCurrentMatches(task, target, tool))
        .isInstanceOf(com.bachelor.toolbox.common.ApiException.class);
  }

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
        xray.toString());
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
