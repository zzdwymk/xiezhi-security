package com.bachelor.toolbox.finding;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class FindingClassificationTests {
  @Test
  void directoryEnumerationLeadsAreNotVulnerabilities() {
    assertFalse(FindingClassification.isVulnerability("INFO", "dir_scan", "STB-DIR-001"));
    // Historical findings may still carry LOW severity; the stable catalog code keeps them in risk points.
    assertFalse(FindingClassification.isVulnerability("LOW", "dir_scan", "STB-DIR-001"));
  }

  @Test
  void confirmedHigherSeverityVulnerabilitiesRemainClassifiedNormally() {
    assertTrue(FindingClassification.isVulnerability("HIGH", "nuclei_scan", "CVE-2025-1234"));
  }
}
