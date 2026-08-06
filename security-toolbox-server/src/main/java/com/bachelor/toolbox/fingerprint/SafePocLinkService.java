package com.bachelor.toolbox.fingerprint;

import com.bachelor.toolbox.vulnerability.NucleiTemplateCatalogService;
import com.bachelor.toolbox.vulnerability.VulnerabilityDefinition;
import com.bachelor.toolbox.vulnerability.VulnerabilityDefinitionRepository;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import org.springframework.stereotype.Service;

@Service
public class SafePocLinkService {
  private static final int MAX_RECOMMENDATIONS = 200;
  private static final String EXECUTION_POLICY = "仅建议通过项目授权任务使用 Nuclei 安全模板执行";
  private static final Comparator<VulnerabilityDefinition> RECOMMENDATION_ORDER =
      Comparator.comparing(VulnerabilityDefinition::getSeverity)
          .thenComparing(VulnerabilityDefinition::getName);

  private final VulnerabilityDefinitionRepository definitions;

  public SafePocLinkService(VulnerabilityDefinitionRepository definitions) {
    this.definitions = definitions;
  }

  public List<Recommendation> recommend(Collection<String> fingerprintIds) {
    Set<String> normalizedIds = normalizeFingerprintIds(fingerprintIds);
    if (normalizedIds.isEmpty()) {
      return List.of();
    }

    return definitions.findAllBySourceType(NucleiTemplateCatalogService.SOURCE_TYPE).stream()
        .filter(this::approvedSafeTemplate)
        .filter(definition -> related(definition, normalizedIds))
        .sorted(RECOMMENDATION_ORDER)
        .limit(MAX_RECOMMENDATIONS)
        .map(this::buildRecommendation)
        .toList();
  }

  private Set<String> normalizeFingerprintIds(Collection<String> fingerprintIds) {
    Set<String> normalizedIds = new HashSet<>();
    if (fingerprintIds == null) {
      return normalizedIds;
    }

    for (String fingerprintId : fingerprintIds) {
      if (fingerprintId == null) {
        continue;
      }
      String normalizedId = fingerprintId.toLowerCase(Locale.ROOT).trim();
      if (!normalizedId.isBlank()) {
        normalizedIds.add(normalizedId);
      }
    }
    return normalizedIds;
  }

  private boolean approvedSafeTemplate(VulnerabilityDefinition definition) {
    if (!definition.isEnabled()
        || !Boolean.TRUE.equals(definition.getSourceActive())
        || !"SAFE".equalsIgnoreCase(definition.getScanSafety())) {
      return false;
    }
    if (!hasValidTemplateReference(definition)) {
      return false;
    }

    boolean official =
        "projectdiscovery/nuclei-templates".equalsIgnoreCase(definition.getSourceName());
    boolean reviewedCustom =
        "VERIFIED".equalsIgnoreCase(definition.getVerificationStatus())
            && Boolean.TRUE.equals(definition.getTemplateSigned());
    return official || reviewedCustom;
  }

  private boolean hasValidTemplateReference(VulnerabilityDefinition definition) {
    return definition.getTemplateRelativePath() != null
        && !definition.getTemplateRelativePath().isBlank()
        && definition.getTemplateSha256() != null
        && definition.getTemplateSha256().matches("[a-fA-F0-9]{64}");
  }

  private boolean related(VulnerabilityDefinition definition, Set<String> fingerprintIds) {
    String searchableText = buildSearchableText(definition);
    return fingerprintIds.stream()
        .anyMatch(
            id -> searchableText.contains(id.replace('-', ' ')) || searchableText.contains(id));
  }

  private String buildSearchableText(VulnerabilityDefinition definition) {
    return String.join(
            " ",
            Objects.toString(definition.getTags(), ""),
            Objects.toString(definition.getName(), ""),
            Objects.toString(definition.getCategory(), ""),
            Objects.toString(definition.getTemplateRelativePath(), ""))
        .toLowerCase(Locale.ROOT);
  }

  private Recommendation buildRecommendation(VulnerabilityDefinition definition) {
    return new Recommendation(
        definition.getVulnerabilityCode(),
        definition.getSourceExternalId(),
        definition.getName(),
        definition.getSeverity(),
        definition.getTemplateRelativePath(),
        definition.getTemplateSha256(),
        definition.getVerificationStatus(),
        EXECUTION_POLICY);
  }

  public record Recommendation(
      String vulnerabilityCode,
      String templateId,
      String name,
      String severity,
      String templatePath,
      String sha256,
      String verificationStatus,
      String executionPolicy) {}
}
