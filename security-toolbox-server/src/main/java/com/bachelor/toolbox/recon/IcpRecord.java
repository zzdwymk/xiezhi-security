package com.bachelor.toolbox.recon;

/**
 * A normalized ICP (site filing) record shared by the built-in MIIT provider and the
 * manually configured API fallback. Field names mirror the source records so the front end
 * can render them without knowing which provider produced the row.
 *
 * <p>All fields are nullable; the UI decides how to omit empty values.
 */
public record IcpRecord(
    String owner,
    String domain,
    String mainLicense,
    String serviceLicense,
    String type,
    String approvedContent,
    String limitAccess,
    String approveDate) {

  public static IcpRecord fromOwner(String domain, String owner, String mainLicense) {
    return new IcpRecord(owner, domain, "", mainLicense, "", "", "否", "");
  }
}