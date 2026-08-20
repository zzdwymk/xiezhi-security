package com.bachelor.toolbox.fingerprint;

import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.common.ApiException;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.List;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
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

  @PostMapping("/poc-recommendations")
  public List<SafePocLinkService.Recommendation> recommendations(
      @RequestBody RecommendationRequest request) {
    return pocLinks.recommend(request.fingerprintIds());
  }

  public record RecommendationRequest(List<String> fingerprintIds) {}
}
