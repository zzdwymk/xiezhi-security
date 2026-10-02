package com.bachelor.toolbox.task;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.dependency.DependencyDetectionService;
import com.bachelor.toolbox.dependency.SystemDependenciesResponse;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.WebTargetResolver;
import com.bachelor.toolbox.tool.ScannerPocSelectionService;
import com.bachelor.toolbox.tool.SecurityTool;
import com.bachelor.toolbox.vulnerability.DetectionRule;
import com.bachelor.toolbox.vulnerability.DetectionRuleRepository;
import com.bachelor.toolbox.vulnerability.VulnerabilityDefinition;
import com.bachelor.toolbox.vulnerability.VulnerabilityDefinitionRepository;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.file.Path;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.test.util.ReflectionTestUtils;

class TaskSnapshotServiceTests {
  @TempDir Path tempDirectory;

  @Test
  void snapshotChecksOnlyCurrentToolAndRejectsChangedVersion() {
    DependencyDetectionService dependencies = mock(DependencyDetectionService.class);
    var first = new SystemDependenciesResponse.DependencyStatus("fscan", "AVAILABLE", "1.8.1", null, false, "test", null, null, null);
    var changed = new SystemDependenciesResponse.DependencyStatus("fscan", "AVAILABLE", "1.8.2", null, false, "test", null, null, null);
    when(dependencies.detectCurrent("fscan")).thenReturn(Optional.of(first), Optional.of(changed));
    TaskSnapshotService service = new TaskSnapshotService(new ObjectMapper().findAndRegisterModules(),
        mock(DetectionRuleRepository.class), dependencies, mock(ScannerPocSelectionService.class), tempDirectory.toString());
    SecurityTool tool = mock(SecurityTool.class);
    when(tool.code()).thenReturn("fscan_scan");
    SecurityTask task = new SecurityTask();
    task.setToolCode("fscan_scan");

    service.capture(task, target(), tool);
    assertThat(task.getToolVersionSnapshot()).isEqualTo("1.8.1");
    assertThatThrownBy(() -> service.assertCurrentMatches(task, target(), tool))
        .isInstanceOf(TaskAuthorizationChangedException.class);
    verify(dependencies, never()).detect();
  }

  @Test
  void hidesSerializationDetailsFromSnapshotFailure() throws Exception {
    ObjectMapper objectMapper = mock(ObjectMapper.class);
    when(objectMapper.writeValueAsString(any()))
        .thenThrow(new JsonProcessingException("jdbc:postgresql://secret-host/toolbox") {});
    TaskSnapshotService service =
        new TaskSnapshotService(
            objectMapper,
            mock(DetectionRuleRepository.class),
            mock(DependencyDetectionService.class),
            mock(ScannerPocSelectionService.class),
            tempDirectory.toString());
    SecurityTask task = new SecurityTask();
    task.setId(42L);
    task.setToolCode("test_tool");

    assertThatThrownBy(() -> service.capture(task, target(), mock(SecurityTool.class)))
        .isInstanceOf(ApiException.class)
        .hasMessage("无法生成任务授权与执行环境快照，请稍后重试")
        .hasMessageNotContaining("secret-host")
        .hasMessageNotContaining("JsonProcessingException")
        .hasMessageNotContaining("jdbc");
  }

  @Test
  void resolvesRuleVersionByRuleCode() {
    DetectionRuleRepository rules = mock(DetectionRuleRepository.class);
    DetectionRule rule = new DetectionRule();
    rule.setRuleCode("RULE-HTTP");
    rule.setVulnerabilityCode("CVE-TEST");
    rule.setName("HTTP 检测规则");
    rule.setToolCode("http_probe");
    when(rules.findByRuleCode("RULE-HTTP")).thenReturn(Optional.of(rule));
    TaskSnapshotService service =
        new TaskSnapshotService(
            new ObjectMapper(),
            rules,
            mock(DependencyDetectionService.class),
            mock(ScannerPocSelectionService.class),
            tempDirectory.toString());

    String version = ReflectionTestUtils.invokeMethod(service, "resolveRuleVersion", "RULE-HTTP");

    assertThat(version).isNotBlank();
    verify(rules).findByRuleCode("RULE-HTTP");
  }

  @ParameterizedTest
  @ValueSource(strings = {"nuclei_scan", "afrog_scan", "xray_scan"})
  void allPocWorkflowSnapshotRetainsSelectionAndRejectsCatalogOrAuthorizationChanges(
      String toolCode) throws Exception {
    ObjectMapper mapper = new ObjectMapper().findAndRegisterModules();
    String source = ScannerPocSelectionService.sourceForTool(toolCode);
    VulnerabilityDefinition first = snapshotPoc(source, "AP-1234567890ABCDEF12345678", "first.yaml");
    VulnerabilityDefinition second = snapshotPoc(source, "AP-ABCDEF1234567890ABCDEF12", "second.yaml");
    VulnerabilityDefinitionRepository definitions = mock(VulnerabilityDefinitionRepository.class);
    when(definitions.findAllBySourceTypeAndEnabledTrueAndSourceActiveTrue(source))
        .thenReturn(List.of(first));
    ScannerPocSelectionService selection = new ScannerPocSelectionService(definitions, mapper,
        tempDirectory.toString(), tempDirectory.toString(), tempDirectory.toString());
    DependencyDetectionService dependencies = mock(DependencyDetectionService.class);
    TaskSnapshotService service = new TaskSnapshotService(mapper,
        mock(DetectionRuleRepository.class), dependencies, selection, tempDirectory.toString());
    SecurityTool tool = mock(SecurityTool.class);
    when(tool.code()).thenReturn(toolCode);
    SecurityTask task = new SecurityTask();
    task.setToolCode(toolCode);
    String requestJson = mapper.writeValueAsString(Map.of("allPocs", true,
        WebTargetResolver.PARAM_RESOLVED_BASES, List.of("https://example.test")));
    task.setRequestJson(requestJson);
    AuthorizedTarget target = target();
    target.setAuthorizationValidFrom(Instant.parse("2026-01-01T00:00:00Z"));
    target.setAuthorizationExpiresAt(Instant.parse("2027-01-01T00:00:00Z"));

    service.capture(task, target, tool);
    service.assertCurrentMatches(task, target, tool);

    assertThat(task.getAuthorizationSnapshotHash()).hasSize(64);
    assertThat(task.getNucleiTemplateHashSnapshot()).hasSize(64);
    assertThat(task.getRequestJson()).isEqualTo(requestJson);
    target.setAllowedPorts("443");
    assertThatThrownBy(() -> service.assertCurrentMatches(task, target, tool))
        .isInstanceOf(TaskAuthorizationChangedException.class);
    target.setAllowedPorts(task.getAllowedPortsSnapshot());
    target.setAuthorizationExpiresAt(Instant.parse("2026-12-01T00:00:00Z"));
    assertThatThrownBy(() -> service.assertCurrentMatches(task, target, tool))
        .isInstanceOf(TaskAuthorizationChangedException.class);
    target.setAuthorizationExpiresAt(task.getAuthorizationExpiresAtSnapshot());
    when(definitions.findAllBySourceTypeAndEnabledTrueAndSourceActiveTrue(source))
        .thenReturn(List.of(first, second));
    assertThatThrownBy(() -> service.assertCurrentMatches(task, target, tool))
        .isInstanceOf(TaskAuthorizationChangedException.class);
    assertThat(task.getRequestJson()).isEqualTo(requestJson);
  }

  private VulnerabilityDefinition snapshotPoc(String source, String code, String filename)
      throws Exception {
    Path file = tempDirectory.resolve(filename);
    Files.writeString(file, "id: " + code);
    VulnerabilityDefinition item = new VulnerabilityDefinition();
    item.setVulnerabilityCode(code);
    item.setSourceExternalId(code);
    item.setSourceType(source);
    item.setSourceActive(true);
    item.setName(code);
    item.setSeverity("INFO");
    item.setTemplateRelativePath(filename);
    item.setTemplateSha256(HexFormat.of().formatHex(
        MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(file))));
    return item;
  }

  private AuthorizedTarget target() {
    AuthorizedTarget target = new AuthorizedTarget();
    target.setId(7L);
    target.setName("授权目标");
    target.setTargetValue("https://example.test");
    target.setTargetType("URL");
    target.setAuthorizationNote("已授权");
    return target;
  }
}
