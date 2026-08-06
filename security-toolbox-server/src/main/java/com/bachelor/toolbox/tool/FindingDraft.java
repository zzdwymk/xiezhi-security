package com.bachelor.toolbox.tool;

public record FindingDraft(
    String title,
    String severity,
    String description,
    String evidence,
    String remediation,
    String vulnerabilityCode) {
  public FindingDraft(
      String title, String severity, String description, String evidence, String remediation) {
    this(title, severity, description, evidence, remediation, null);
  }
}
