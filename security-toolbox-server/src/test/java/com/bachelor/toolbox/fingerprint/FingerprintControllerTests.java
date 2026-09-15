package com.bachelor.toolbox.fingerprint;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.common.ApiException;
import java.lang.reflect.RecordComponent;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;

class FingerprintControllerTests {
  private final FingerprintRuleCatalog catalog = mock(FingerprintRuleCatalog.class);
  private final SafePocLinkService pocLinks = mock(SafePocLinkService.class);
  private final AuditService audit = mock(AuditService.class);
  private final FingerprintController controller =
      new FingerprintController(catalog, pocLinks, audit);

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

    PutMapping updateMapping =
        FingerprintController.class
            .getDeclaredMethod("update", jakarta.servlet.http.HttpServletRequest.class)
            .getAnnotation(PutMapping.class);
    assertThat(updateMapping.value()).containsExactly("/catalog");
    assertThat(updateMapping.consumes()).containsExactly("application/json");

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
        .containsExactly("version", "sha256", "ruleCount", "source");
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
            "header",
            "faviconHash",
            "faviconMd5");
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
  void delegatesCatalogAndRecommendationOperationsWithoutTransformingData() throws Exception {
    FingerprintRuleCatalog.CatalogInfo current =
        new FingerprintRuleCatalog.CatalogInfo("v1", "current", 2);
    FingerprintRuleCatalog.CatalogInfo reloaded =
        new FingerprintRuleCatalog.CatalogInfo("v2", "reloaded", 3);
    byte[] updateContent = "{}".getBytes();
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
    when(catalog.update(updateContent)).thenReturn(reloaded);
    MockHttpServletRequest updateRequest = new MockHttpServletRequest();
    updateRequest.setContent(updateContent);
    when(pocLinks.recommend(fingerprintIds)).thenReturn(recommendations);

    assertThat(controller.catalog()).isSameAs(current);
    assertThat(controller.reload()).isSameAs(reloaded);
    assertThat(controller.update(updateRequest)).isSameAs(reloaded);
    assertThat(controller.recommendations(request)).isSameAs(recommendations);

    verify(catalog).info();
    verify(catalog).reload();
    verify(catalog).update(updateContent);
    verify(audit)
        .recordStructured(
            "UPDATE_FINGERPRINT_CATALOG",
            "FINGERPRINT_CATALOG",
            null,
            java.util.Map.of(
                "version", reloaded.version(),
                "ruleCount", reloaded.ruleCount(),
                "sha256", reloaded.sha256(),
                "source", reloaded.source().name()),
            "SUCCESS");
    verify(pocLinks).recommend(fingerprintIds);
  }

  @Test
  void rejectsOversizedRequestBeforeReadingOrUpdatingTheCatalog() {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.setContent(new byte[FingerprintRuleCatalog.MAX_BYTES + 1]);

    assertThatThrownBy(() -> controller.update(request))
        .isInstanceOf(ApiException.class)
        .hasMessage("指纹规则文件超过 2MB 限制");

    verifyNoInteractions(catalog, pocLinks, audit);
  }

  @Test
  void exposesRuleManagementPathsAndReturns() throws Exception {
    FingerprintRuleCatalog.Rule rule =
        new FingerprintRuleCatalog.Rule(
            "new-rule-id",
            "New Rule",
            "TEST",
            80,
            Map.of("server", List.of("marker")),
            List.of("body-marker"),
            List.of(),
            List.of(),
            List.of(),
            List.of(),
            List.of());

    GetMapping rulesMapping =
        FingerprintController.class.getDeclaredMethod("rules").getAnnotation(GetMapping.class);
    assertThat(rulesMapping.value()).containsExactly("/rules");

    PostMapping addMapping =
        FingerprintController.class
            .getDeclaredMethod("addRule", FingerprintRuleCatalog.Rule.class)
            .getAnnotation(PostMapping.class);
    assertThat(addMapping.value()).containsExactly("/rules");
    assertThat(addMapping.consumes()).containsExactly("application/json");

    PutMapping editMapping =
        FingerprintController.class
            .getDeclaredMethod(
                "updateRule", String.class, FingerprintRuleCatalog.Rule.class)
            .getAnnotation(PutMapping.class);
    assertThat(editMapping.value()).containsExactly("/rules/{ruleId}");
    String pathVarValue =
        FingerprintController.class
            .getDeclaredMethod("updateRule", String.class, FingerprintRuleCatalog.Rule.class)
            .getParameters()[0]
            .getAnnotation(PathVariable.class)
            .value();
    assertThat(pathVarValue).isIn("ruleId", "");

    DeleteMapping deleteMapping =
        FingerprintController.class
            .getDeclaredMethod("deleteRule", String.class)
            .getAnnotation(DeleteMapping.class);
    assertThat(deleteMapping.value()).containsExactly("/rules/{ruleId}");

    PostMapping validateMapping =
        FingerprintController.class
            .getDeclaredMethod("validateRule", FingerprintRuleCatalog.Rule.class)
            .getAnnotation(PostMapping.class);
    assertThat(validateMapping.value()).containsExactly("/rules/validate");
  }

  @Test
  void delegatesRuleCrudAndValidationToTheCatalog() {
    FingerprintRuleCatalog.Rule rule =
        new FingerprintRuleCatalog.Rule(
            "spring-custom",
            "Spring Custom",
            "FRAMEWORK",
            25,
            Map.of("x-powered-by", List.of("spring-custom")),
            List.of("spring-custom-token"),
            List.of(),
            List.of(),
            List.of(),
            List.of(),
            List.of());
    FingerprintRuleCatalog.CatalogInfo added =
        new FingerprintRuleCatalog.CatalogInfo("v2", "new-sha", 3);
    FingerprintRuleCatalog.CatalogInfo deleted =
        new FingerprintRuleCatalog.CatalogInfo("v2", "other-sha", 2);
    FingerprintRuleCatalog.RuleEditResult edited =
        new FingerprintRuleCatalog.RuleEditResult(
            new FingerprintRuleCatalog.CatalogInfo("v2", "edit-sha", 3), rule);
    Map<String, String> issues = Map.of("confidence", "置信度无效");

    when(catalog.rules()).thenReturn(List.of(rule));
    when(catalog.validateRule(rule)).thenReturn(issues);
    when(catalog.addRule(rule)).thenReturn(added);
    when(catalog.updateRule("spring-custom", rule)).thenReturn(edited);
    when(catalog.deleteRule("spring-custom")).thenReturn(deleted);

    assertThat(controller.rules()).containsExactly(rule);
    assertThat(controller.validateRule(rule)).isEqualTo(issues);
    FingerprintRuleCatalog.CatalogInfo addResult = controller.addRule(rule);
    assertThat(addResult).isSameAs(added);
    assertThat(controller.updateRule("spring-custom", rule)).isSameAs(edited);
    assertThat(controller.deleteRule("spring-custom")).isSameAs(deleted);

    verify(catalog).rules();
    verify(catalog).validateRule(rule);
    verify(catalog).addRule(rule);
    verify(catalog).updateRule("spring-custom", rule);
    verify(catalog).deleteRule("spring-custom");
    verify(audit)
        .recordStructured(
            "ADD_FINGERPRINT_RULE", "FINGERPRINT_RULE", "spring-custom", null, "SUCCESS");
    verify(audit)
        .recordStructured(
            "UPDATE_FINGERPRINT_RULE", "FINGERPRINT_RULE", "spring-custom", null, "SUCCESS");
    verify(audit)
        .recordStructured(
            "DELETE_FINGERPRINT_RULE", "FINGERPRINT_RULE", "spring-custom", null, "SUCCESS");
  }

  private List<String> recordComponentNames(Class<?> recordType) {
    return Arrays.stream(recordType.getRecordComponents()).map(RecordComponent::getName).toList();
  }
}
