package com.bachelor.toolbox.tool;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

public final class CommandLogFormatter {
  private static final Set<String> SENSITIVE_FLAGS =
      Set.of(
          "--password",
          "--passwd",
          "--token",
          "--api-key",
          "--apikey",
          "--secret",
          "--authorization",
          "--cookie",
          "-password",
          "-token");
  private static final Pattern SENSITIVE_ASSIGNMENT =
      Pattern.compile(
          "(?i)^([^=]*(?:password|passwd|token|api[-_]?key|secret|authorization|cookie)[^=]*)=(.*)$");

  private CommandLogFormatter() {}

  public static String format(List<String> rawCommand) {
    if (rawCommand == null || rawCommand.isEmpty()) return "<empty>";
    List<String> safe = new ArrayList<>(rawCommand.size());
    boolean redactNext = false;
    for (String raw : rawCommand) {
      String value = raw == null ? "" : raw;
      if (redactNext) {
        safe.add("[REDACTED]");
        redactNext = false;
        continue;
      }
      String lower = value.toLowerCase(Locale.ROOT);
      if (SENSITIVE_FLAGS.contains(lower)) {
        safe.add(value);
        redactNext = true;
        continue;
      }
      if (value.contains("://")) {
        safe.add(sanitizeUri(value));
        continue;
      }
      var assignment = SENSITIVE_ASSIGNMENT.matcher(value);
      if (assignment.matches()) {
        safe.add(assignment.group(1) + "=[REDACTED]");
        continue;
      }
      safe.add(sanitizeUri(value));
    }
    return safe.stream()
        .map(CommandLogFormatter::quote)
        .reduce((left, right) -> left + " " + right)
        .orElse("<empty>");
  }

  private static String sanitizeUri(String value) {
    try {
      URI uri = URI.create(value);
      if (uri.getScheme() == null
          || uri.getHost() == null
          || (uri.getUserInfo() == null && uri.getRawQuery() == null)) return value;
      String query = uri.getRawQuery();
      if (query != null) {
        query =
            Pattern.compile("(?i)(^|&)([^=&]*(?:password|token|api[-_]?key|secret)[^=&]*)=[^&]*")
                .matcher(query)
                .replaceAll("$1$2=[REDACTED]");
      }
      return new URI(
              uri.getScheme(),
              null,
              uri.getHost(),
              uri.getPort(),
              uri.getRawPath(),
              query,
              uri.getRawFragment())
          .toString();
    } catch (Exception ignored) {
      return value;
    }
  }

  private static String quote(String value) {
    if (!value.isEmpty()
        && value
            .chars()
            .allMatch(ch -> Character.isLetterOrDigit(ch) || "-._/:,=[]".indexOf(ch) >= 0))
      return value;
    return '"' + value.replace("\\", "\\\\").replace("\"", "\\\"") + '"';
  }
}
