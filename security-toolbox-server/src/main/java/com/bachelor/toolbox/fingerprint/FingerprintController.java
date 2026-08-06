package com.bachelor.toolbox.fingerprint;

import java.util.List;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/fingerprints")
public class FingerprintController {
  private final FingerprintRuleCatalog catalog;
  private final SafePocLinkService pocLinks;

  public FingerprintController(FingerprintRuleCatalog catalog, SafePocLinkService pocLinks) {
    this.catalog = catalog;
    this.pocLinks = pocLinks;
  }

  @GetMapping("/catalog")
  public FingerprintRuleCatalog.CatalogInfo catalog() {
    return catalog.info();
  }

  @PostMapping("/catalog/reload")
  public FingerprintRuleCatalog.CatalogInfo reload() {
    return catalog.reload();
  }

  @PostMapping("/poc-recommendations")
  public List<SafePocLinkService.Recommendation> recommendations(
      @RequestBody RecommendationRequest request) {
    return pocLinks.recommend(request.fingerprintIds());
  }

  public record RecommendationRequest(List<String> fingerprintIds) {}
}
