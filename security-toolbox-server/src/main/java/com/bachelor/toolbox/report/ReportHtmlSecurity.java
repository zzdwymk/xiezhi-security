package com.bachelor.toolbox.report;

import java.util.UUID;

/** Adds a nonce-based CSP to generated report HTML, including reports opened from disk. */
final class ReportHtmlSecurity {
  private ReportHtmlSecurity() {}

  static String secure(String html) {
    if (html == null || html.isBlank()) {
      return "";
    }
    String nonce = UUID.randomUUID().toString().replace("-", "");
    String policy =
        "default-src 'none'; style-src 'unsafe-inline'; img-src data:; font-src data:; "
            + "script-src 'nonce-"
            + nonce
            + "'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";
    String meta =
        "<meta http-equiv=\"Content-Security-Policy\" content=\""
            + policy
            + "\">";
    String secured = html.replaceFirst("<head>", "<head>" + meta);
    // The only generated script is the report filter; user-controlled text is escaped elsewhere.
    return secured.replace("<script>", "<script nonce=\"" + nonce + "\">");
  }
}
