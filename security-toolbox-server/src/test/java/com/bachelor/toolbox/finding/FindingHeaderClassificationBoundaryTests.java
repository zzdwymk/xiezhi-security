package com.bachelor.toolbox.finding;
import static org.assertj.core.api.Assertions.assertThat;
import org.junit.jupiter.api.Test;
class FindingHeaderClassificationBoundaryTests {
 @Test void unrelatedNotSetPhraseCannotSuppressHighRiskVulnerability(){
  assertThat(FindingClassification.isVulnerability("HIGH","nuclei_scan","CVE-QA-001",
      "Authentication bypass", "Access control is not set, allowing unauthorized execution")).isTrue();
 }
 @Test void actualMissingCspAndClickjackingHeadersRemainRiskPoints(){
  assertThat(FindingClassification.isVulnerability("HIGH","zap_scan","QA-CSP",
      "CSP header not set", "Missing security response headers")).isFalse();
  assertThat(FindingClassification.isVulnerability("HIGH","zap_scan","QA-FRAME",
      "Missing anti-clickjacking header", "")).isFalse();
 }
}
