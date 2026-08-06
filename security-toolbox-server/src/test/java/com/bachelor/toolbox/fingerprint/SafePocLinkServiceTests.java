package com.bachelor.toolbox.fingerprint;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.vulnerability.NucleiTemplateCatalogService;
import com.bachelor.toolbox.vulnerability.VulnerabilityDefinition;
import com.bachelor.toolbox.vulnerability.VulnerabilityDefinitionRepository;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;

class SafePocLinkServiceTests {
  private final VulnerabilityDefinitionRepository definitions =
      mock(VulnerabilityDefinitionRepository.class);
  private final SafePocLinkService service = new SafePocLinkService(definitions);

  @Test
  void skipsCatalogLookupWhenNoUsableFingerprintIdIsProvided() {
    assertThat(service.recommend(null)).isEmpty();
    assertThat(service.recommend(Arrays.asList(null, "", "   "))).isEmpty();

    verify(definitions, never()).findAllBySourceType(NucleiTemplateCatalogService.SOURCE_TYPE);
  }

  @Test
  void returnsOnlyRelatedApprovedSafeTemplatesInOriginalSortOrder() {
    VulnerabilityDefinition official = approvedDefinition("NT-LOW", "Zulu Spring Check", "LOW");
    VulnerabilityDefinition reviewedCustom =
        approvedDefinition("NT-HIGH", "Alpha Spring Check", "HIGH");
    reviewedCustom.setSourceName("internal/templates");
    reviewedCustom.setVerificationStatus("VERIFIED");
    reviewedCustom.setTemplateSigned(true);

    VulnerabilityDefinition unsafe = approvedDefinition("NT-UNSAFE", "Unsafe", "HIGH");
    unsafe.setScanSafety("UNSAFE");
    VulnerabilityDefinition unsignedCustom = approvedDefinition("NT-UNSIGNED", "Unsigned", "HIGH");
    unsignedCustom.setSourceName("internal/templates");
    unsignedCustom.setVerificationStatus("VERIFIED");
    unsignedCustom.setTemplateSigned(false);
    VulnerabilityDefinition invalidDigest =
        approvedDefinition("NT-DIGEST", "Invalid Digest", "HIGH");
    invalidDigest.setTemplateSha256("not-a-digest");
    VulnerabilityDefinition unrelated = approvedDefinition("NT-OTHER", "Unrelated Check", "MEDIUM");
    unrelated.setTags("wordpress");
    unrelated.setCategory("cms");
    unrelated.setTemplateRelativePath("http/wordpress/check.yaml");

    when(definitions.findAllBySourceType(NucleiTemplateCatalogService.SOURCE_TYPE))
        .thenReturn(
            List.of(official, reviewedCustom, unsafe, unsignedCustom, invalidDigest, unrelated));

    List<SafePocLinkService.Recommendation> result = service.recommend(List.of("  SPRING-BOOT  "));

    assertThat(result)
        .extracting(SafePocLinkService.Recommendation::vulnerabilityCode)
        .containsExactly("NT-HIGH", "NT-LOW");
    assertThat(result)
        .allSatisfy(
            recommendation -> {
              assertThat(recommendation.sha256()).hasSize(64);
              assertThat(recommendation.executionPolicy()).isEqualTo("仅建议通过项目授权任务使用 Nuclei 安全模板执行");
            });
    verify(definitions).findAllBySourceType(NucleiTemplateCatalogService.SOURCE_TYPE);
  }

  @Test
  void limitsRecommendationsAfterSorting() {
    List<VulnerabilityDefinition> candidates = new ArrayList<>();
    for (int index = 204; index >= 0; index--) {
      candidates.add(
          approvedDefinition("NT-" + index, "Spring Check %03d".formatted(index), "LOW"));
    }
    when(definitions.findAllBySourceType(NucleiTemplateCatalogService.SOURCE_TYPE))
        .thenReturn(candidates);

    List<SafePocLinkService.Recommendation> result = service.recommend(List.of("spring-boot"));

    assertThat(result).hasSize(200);
    assertThat(result.get(0).name()).isEqualTo("Spring Check 000");
    assertThat(result.get(199).name()).isEqualTo("Spring Check 199");
  }

  private VulnerabilityDefinition approvedDefinition(
      String vulnerabilityCode, String name, String severity) {
    VulnerabilityDefinition definition = new VulnerabilityDefinition();
    definition.setVulnerabilityCode(vulnerabilityCode);
    definition.setSourceExternalId("template-" + vulnerabilityCode);
    definition.setName(name);
    definition.setSeverity(severity);
    definition.setCategory("spring boot framework");
    definition.setTags("java,spring boot");
    definition.setTemplateRelativePath("http/spring-boot/check.yaml");
    definition.setTemplateSha256("a".repeat(64));
    definition.setVerificationStatus("OFFICIAL_RELEASE_DIGEST_PRESENT");
    definition.setSourceName("projectdiscovery/nuclei-templates");
    definition.setScanSafety("SAFE");
    definition.setSourceActive(true);
    definition.setEnabled(true);
    return definition;
  }
}
