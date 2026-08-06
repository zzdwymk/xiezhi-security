package com.bachelor.toolbox.fingerprint;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.lang.reflect.RecordComponent;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

class FingerprintControllerTests {
  private final FingerprintRuleCatalog catalog = mock(FingerprintRuleCatalog.class);
  private final SafePocLinkService pocLinks = mock(SafePocLinkService.class);
  private final FingerprintController controller = new FingerprintController(catalog, pocLinks);

  @Test
  void keepsApiPathsCompatible() throws NoSuchMethodException {
    RequestMapping baseMapping = FingerprintController.class.getAnnotation(RequestMapping.class);
    assertThat(baseMapping.value()).containsExactly("/api/fingerprints");

    GetMapping catalogMapping =
        FingerprintController.class.getDeclaredMethod("catalog").getAnnotation(GetMapping.class);
    assertThat(catalogMapping.value()).containsExactly("/catalog");

    PostMapping reloadMapping =
        FingerprintController.class.getDeclaredMethod("reload").getAnnotation(PostMapping.class);
    assertThat(reloadMapping.value()).containsExactly("/catalog/reload");

    PostMapping recommendationsMapping =
        FingerprintController.class
            .getDeclaredMethod("recommendations", FingerprintController.RecommendationRequest.class)
            .getAnnotation(PostMapping.class);
    assertThat(recommendationsMapping.value()).containsExactly("/poc-recommendations");
  }

  @Test
  void keepsRequestAndResponseJsonFieldsCompatible() {
    assertThat(recordComponentNames(FingerprintController.RecommendationRequest.class))
        .containsExactly("fingerprintIds");
    assertThat(recordComponentNames(FingerprintRuleCatalog.CatalogInfo.class))
        .containsExactly("version", "sha256", "ruleCount");
    assertThat(recordComponentNames(FingerprintRuleCatalog.Catalog.class))
        .containsExactly("version", "rules");
    assertThat(recordComponentNames(FingerprintRuleCatalog.Rule.class))
        .containsExactly(
            "id",
            "name",
            "category",
            "confidence",
            "headers",
            "body",
            "cookies",
            "title",
            "header");
    assertThat(recordComponentNames(FingerprintMatcher.Match.class))
        .containsExactly("id", "name", "category", "confidence", "evidence");
    assertThat(recordComponentNames(FingerprintMatcher.Result.class))
        .containsExactly("catalog", "title", "matches");
    assertThat(recordComponentNames(SafePocLinkService.Recommendation.class))
        .containsExactly(
            "vulnerabilityCode",
            "templateId",
            "name",
            "severity",
            "templatePath",
            "sha256",
            "verificationStatus",
            "executionPolicy");
  }

  @Test
  void delegatesCatalogAndRecommendationOperationsWithoutTransformingData() {
    FingerprintRuleCatalog.CatalogInfo current =
        new FingerprintRuleCatalog.CatalogInfo("v1", "current", 2);
    FingerprintRuleCatalog.CatalogInfo reloaded =
        new FingerprintRuleCatalog.CatalogInfo("v2", "reloaded", 3);
    List<String> fingerprintIds = List.of("spring-boot", "nginx");
    FingerprintController.RecommendationRequest request =
        new FingerprintController.RecommendationRequest(fingerprintIds);
    List<SafePocLinkService.Recommendation> recommendations =
        List.of(
            new SafePocLinkService.Recommendation(
                "NT-1",
                "template-1",
                "Spring Test",
                "LOW",
                "http/spring.yaml",
                "a".repeat(64),
                "VERIFIED",
                "仅建议通过项目授权任务使用 Nuclei 安全模板执行"));
    when(catalog.info()).thenReturn(current);
    when(catalog.reload()).thenReturn(reloaded);
    when(pocLinks.recommend(fingerprintIds)).thenReturn(recommendations);

    assertThat(controller.catalog()).isSameAs(current);
    assertThat(controller.reload()).isSameAs(reloaded);
    assertThat(controller.recommendations(request)).isSameAs(recommendations);

    verify(catalog).info();
    verify(catalog).reload();
    verify(pocLinks).recommend(fingerprintIds);
  }

  private List<String> recordComponentNames(Class<?> recordType) {
    return Arrays.stream(recordType.getRecordComponents()).map(RecordComponent::getName).toList();
  }
}
