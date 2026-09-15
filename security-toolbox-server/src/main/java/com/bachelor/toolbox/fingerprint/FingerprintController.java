package com.bachelor.toolbox.fingerprint;

import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.common.ApiException;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/fingerprints")
public class FingerprintController {
  private final FingerprintRuleCatalog catalog;
  private final SafePocLinkService pocLinks;
  private final AuditService audit;

  public FingerprintController(
      FingerprintRuleCatalog catalog, SafePocLinkService pocLinks, AuditService audit) {
    this.catalog = catalog;
    this.pocLinks = pocLinks;
    this.audit = audit;
  }

  @GetMapping("/catalog")
  public FingerprintRuleCatalog.CatalogInfo catalog() {
    return catalog.info();
  }

  @PostMapping("/catalog/reload")
  public FingerprintRuleCatalog.CatalogInfo reload() {
    return catalog.reload();
  }

  @PutMapping(value = "/catalog", consumes = MediaType.APPLICATION_JSON_VALUE)
  public FingerprintRuleCatalog.CatalogInfo update(HttpServletRequest request) throws IOException {
    long declaredBytes = request.getContentLengthLong();
    if (declaredBytes > FingerprintRuleCatalog.MAX_BYTES) {
      throw new ApiException("指纹规则文件超过 2MB 限制");
    }
    byte[] content = request.getInputStream().readNBytes(FingerprintRuleCatalog.MAX_BYTES + 1);
    FingerprintRuleCatalog.CatalogInfo updated = catalog.update(content);
    audit.recordStructured(
        "UPDATE_FINGERPRINT_CATALOG",
        "FINGERPRINT_CATALOG",
        null,
        java.util.Map.of(
            "version", updated.version(),
            "ruleCount", updated.ruleCount(),
            "sha256", updated.sha256(),
            "source", updated.source().name()),
        "SUCCESS");
    return updated;
  }

  @GetMapping("/rules")
  public List<FingerprintRuleCatalog.Rule> rules() {
    return catalog.rules();
  }

  /** Validates a single rule without persisting it. Returns a field->problem map. */
  @PostMapping("/rules/validate")
  public Map<String, String> validateRule(@RequestBody FingerprintRuleCatalog.Rule rule) {
    return catalog.validateRule(rule);
  }

  @PostMapping(value = "/rules", consumes = MediaType.APPLICATION_JSON_VALUE)
  public FingerprintRuleCatalog.CatalogInfo addRule(@RequestBody FingerprintRuleCatalog.Rule rule) {
    FingerprintRuleCatalog.CatalogInfo updated = catalog.addRule(rule);
    audit.recordStructured("ADD_FINGERPRINT_RULE", "FINGERPRINT_RULE", rule.id(), null, "SUCCESS");
    return updated;
  }

  @PutMapping(value = "/rules/{ruleId}")
  public FingerprintRuleCatalog.RuleEditResult updateRule(
      @PathVariable String ruleId, @RequestBody FingerprintRuleCatalog.Rule rule) {
    FingerprintRuleCatalog.RuleEditResult updated = catalog.updateRule(ruleId, rule);
    audit.recordStructured(
        "UPDATE_FINGERPRINT_RULE", "FINGERPRINT_RULE", ruleId, null, "SUCCESS");
    return updated;
  }

  @DeleteMapping("/rules/{ruleId}")
  public FingerprintRuleCatalog.CatalogInfo deleteRule(@PathVariable String ruleId) {
    FingerprintRuleCatalog.CatalogInfo updated = catalog.deleteRule(ruleId);
    audit.recordStructured(
        "DELETE_FINGERPRINT_RULE", "FINGERPRINT_RULE", ruleId, null, "SUCCESS");
    return updated;
  }

  @PostMapping("/poc-recommendations")
  public List<SafePocLinkService.Recommendation> recommendations(
      @RequestBody RecommendationRequest request) {
    return pocLinks.recommend(request.fingerprintIds());
  }

  public record RecommendationRequest(List<String> fingerprintIds) {}
}
