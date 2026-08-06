package com.bachelor.toolbox.fingerprint;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class FingerprintMatcherTests {
  @Test
  void matchesEveryEvidenceTypeAndPreservesEvidenceOrder() {
    Map<String, List<String>> expectedHeaders = new LinkedHashMap<>();
    expectedHeaders.put("server", List.of("nginx"));
    FingerprintRuleCatalog.Rule rule =
        rule(
            "complete-rule",
            "Complete Rule",
            73,
            expectedHeaders,
            List.of("body marker"),
            List.of("sessionid"),
            List.of("my console"),
            List.of("x-powered-by: php"));
    FingerprintMatcher matcher = matcher(List.of(rule));

    Map<String, List<String>> headers = new LinkedHashMap<>();
    headers.put("Server", List.of("NGINX/1.27"));
    headers.put("X-Powered-By", List.of("PHP/8.3"));
    headers.put("Set-Cookie", List.of("SESSIONID=abc", "theme=dark"));

    FingerprintMatcher.Result result =
        matcher.match(headers, "<title>  My\n Console </title><div>BODY MARKER</div>");

    assertThat(result.title()).isEqualTo("My Console");
    assertThat(result.matches())
        .singleElement()
        .satisfies(
            match -> {
              assertThat(match.id()).isEqualTo("complete-rule");
              assertThat(match.confidence()).isEqualTo(73);
              assertThat(match.evidence())
                  .containsExactly("header:server", "header", "body", "cookie", "title");
            });
  }

  @Test
  void sortsByDescendingConfidenceAndKeepsCatalogOrderForTies() {
    FingerprintMatcher matcher =
        matcher(
            List.of(
                bodyRule("low", 20, "signature"),
                bodyRule("first-high", 80, "signature"),
                bodyRule("second-high", 80, "signature")));

    FingerprintMatcher.Result result = matcher.match(Map.of(), "SIGNATURE");

    assertThat(result.matches())
        .extracting(FingerprintMatcher.Match::id)
        .containsExactly("first-high", "second-high", "low");
    assertThat(result.matches())
        .extracting(FingerprintMatcher.Match::confidence)
        .containsExactly(80, 80, 20);
  }

  @Test
  void treatsAnEmptyHeaderPatternAsAHeaderPresenceCheck() {
    FingerprintRuleCatalog.Rule rule =
        rule("presence", "Presence", 60, Map.of("x-present", List.of("")), null, null, null, null);
    FingerprintMatcher matcher = matcher(List.of(rule));

    assertThat(matcher.match(Map.of("X-Present", List.of("yes")), null).matches())
        .extracting(FingerprintMatcher.Match::id)
        .containsExactly("presence");
    assertThat(matcher.match(Map.of("X-Present", List.of()), null).matches()).isEmpty();
  }

  @Test
  void ignoresUnconfiguredRulesAndBodyContentAfterOneMebibyte() {
    FingerprintRuleCatalog.Rule unconfigured =
        rule("unconfigured", "Unconfigured", 90, Map.of(), null, null, null, null);
    FingerprintRuleCatalog.Rule outsideLimit = bodyRule("outside-limit", 80, "outside-limit");
    FingerprintMatcher matcher = matcher(List.of(unconfigured, outsideLimit));
    String body = "a".repeat(1024 * 1024) + "outside-limit";

    FingerprintMatcher.Result result = matcher.match(null, body);

    assertThat(result.title()).isEmpty();
    assertThat(result.matches()).isEmpty();
  }

  private FingerprintMatcher matcher(List<FingerprintRuleCatalog.Rule> rules) {
    FingerprintRuleCatalog catalog = mock(FingerprintRuleCatalog.class);
    FingerprintRuleCatalog.CatalogInfo info =
        new FingerprintRuleCatalog.CatalogInfo("test", "abc123", rules.size());
    when(catalog.rules()).thenReturn(rules);
    when(catalog.info()).thenReturn(info);
    return new FingerprintMatcher(catalog);
  }

  private FingerprintRuleCatalog.Rule bodyRule(String id, int confidence, String marker) {
    return rule(id, id, confidence, null, List.of(marker), null, null, null);
  }

  private FingerprintRuleCatalog.Rule rule(
      String id,
      String name,
      int confidence,
      Map<String, List<String>> headers,
      List<String> body,
      List<String> cookies,
      List<String> title,
      List<String> header) {
    return new FingerprintRuleCatalog.Rule(
        id, name, "FRAMEWORK", confidence, headers, body, cookies, title, header);
  }
}
