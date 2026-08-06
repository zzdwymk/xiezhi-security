package com.bachelor.toolbox.fingerprint;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.springframework.stereotype.Service;

@Service
public class FingerprintMatcher {
  private static final int MAX_BODY_CHARACTERS = 1024 * 1024;
  private static final Pattern TITLE = Pattern.compile("(?is)<title[^>]*>(.*?)</title>");

  private final FingerprintRuleCatalog catalog;

  public FingerprintMatcher(FingerprintRuleCatalog catalog) {
    this.catalog = catalog;
  }

  public Result match(Map<String, List<String>> headers, String body) {
    MatchContext context = createContext(headers, body);
    List<Match> matches = new ArrayList<>();

    for (FingerprintRuleCatalog.Rule rule : catalog.rules()) {
      Match match = matchRule(rule, context);
      if (match != null) {
        matches.add(match);
      }
    }

    matches.sort(Comparator.comparingInt(Match::confidence).reversed());
    return buildResult(context, matches);
  }

  private MatchContext createContext(Map<String, List<String>> headers, String body) {
    String boundedBody = limitBody(body);
    return new MatchContext(
        headers,
        boundedBody,
        extractTitle(boundedBody),
        String.join(";", headerValues(headers, "set-cookie")),
        buildHeaderText(headers));
  }

  private Match matchRule(FingerprintRuleCatalog.Rule rule, MatchContext context) {
    List<String> evidence = new ArrayList<>();
    boolean configured = rule.headers() != null && !rule.headers().isEmpty();
    boolean matched = matchNamedHeaders(rule.headers(), context.headers(), evidence);

    configured |= isConfigured(rule.header());
    matched |= addEvidenceIfMatched(context.headerText(), rule.header(), "header", evidence);

    configured |= isConfigured(rule.body());
    matched |= addEvidenceIfMatched(context.body(), rule.body(), "body", evidence);

    configured |= isConfigured(rule.cookies());
    matched |= addEvidenceIfMatched(context.cookies(), rule.cookies(), "cookie", evidence);

    configured |= isConfigured(rule.title());
    matched |= addEvidenceIfMatched(context.title(), rule.title(), "title", evidence);

    if (!configured || !matched) {
      return null;
    }
    return buildMatch(rule, evidence);
  }

  private boolean matchNamedHeaders(
      Map<String, List<String>> expectedHeaders,
      Map<String, List<String>> actualHeaders,
      List<String> evidence) {
    if (expectedHeaders == null) {
      return false;
    }

    boolean matched = false;
    for (Map.Entry<String, List<String>> expected : expectedHeaders.entrySet()) {
      String actual = String.join(";", headerValues(actualHeaders, expected.getKey()));
      if (containsAny(actual, expected.getValue())) {
        matched = true;
        evidence.add("header:" + expected.getKey());
      }
    }
    return matched;
  }

  private boolean addEvidenceIfMatched(
      String actual, List<String> expected, String evidenceType, List<String> evidence) {
    if (!isConfigured(expected) || !containsAny(actual, expected)) {
      return false;
    }
    evidence.add(evidenceType);
    return true;
  }

  private boolean isConfigured(List<String> values) {
    return values != null && !values.isEmpty();
  }

  private boolean containsAny(String actual, List<String> values) {
    String normalizedActual = normalize(actual);
    if (values == null) {
      return false;
    }

    for (String value : values) {
      if (value == null) {
        continue;
      }
      if (value.isEmpty()
          ? !normalizedActual.isEmpty()
          : normalizedActual.contains(normalize(value))) {
        return true;
      }
    }
    return false;
  }

  private String normalize(String value) {
    return value == null ? "" : value.toLowerCase(Locale.ROOT);
  }

  private String limitBody(String body) {
    if (body == null) {
      return "";
    }
    return body.substring(0, Math.min(body.length(), MAX_BODY_CHARACTERS));
  }

  private String buildHeaderText(Map<String, List<String>> headers) {
    if (headers == null) {
      return "";
    }

    StringBuilder text = new StringBuilder();
    headers.forEach(
        (name, values) ->
            text.append(name)
                .append(": ")
                .append(values == null ? "" : String.join(",", values))
                .append('\n'));
    return text.toString();
  }

  private List<String> headerValues(Map<String, List<String>> headers, String name) {
    if (headers == null) {
      return List.of();
    }

    for (Map.Entry<String, List<String>> header : headers.entrySet()) {
      if (header.getKey().equalsIgnoreCase(name)) {
        return header.getValue() == null ? List.of() : header.getValue();
      }
    }
    return List.of();
  }

  private String extractTitle(String body) {
    Matcher matcher = TITLE.matcher(body);
    if (!matcher.find()) {
      return "";
    }
    return matcher.group(1).replaceAll("\\s+", " ").trim();
  }

  private Match buildMatch(FingerprintRuleCatalog.Rule rule, List<String> evidence) {
    return new Match(rule.id(), rule.name(), rule.category(), calculateConfidence(rule), evidence);
  }

  private int calculateConfidence(FingerprintRuleCatalog.Rule rule) {
    return rule.confidence();
  }

  private Result buildResult(MatchContext context, List<Match> matches) {
    return new Result(catalog.info(), context.title(), matches);
  }

  private record MatchContext(
      Map<String, List<String>> headers,
      String body,
      String title,
      String cookies,
      String headerText) {}

  public record Match(
      String id, String name, String category, int confidence, List<String> evidence) {}

  public record Result(
      FingerprintRuleCatalog.CatalogInfo catalog, String title, List<Match> matches) {}
}
