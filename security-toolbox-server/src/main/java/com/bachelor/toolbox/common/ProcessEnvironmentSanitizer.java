package com.bachelor.toolbox.common;

import java.util.Locale;
import java.util.Map;
import java.util.Set;

/** Prevents application credentials from being inherited by external security tools. */
public final class ProcessEnvironmentSanitizer {
  private static final Set<String> SENSITIVE_NAMES =
      Set.of(
          "ADMIN_PASSWORD",
          "JWT_SECRET",
          "TRAFFIC_MITM_CA_PASSWORD",
          "AI_API_KEY",
          "AI_RUNTIME_TOKEN",
          "AI_RUNTIME_API_KEY",
          "OPENAI_API_KEY",
          "ANTHROPIC_API_KEY",
          "AZURE_OPENAI_API_KEY");

  private ProcessEnvironmentSanitizer() {}

  public static ProcessBuilder sanitize(ProcessBuilder builder) {
    Map<String, String> environment = builder.environment();
    environment.keySet().removeIf(ProcessEnvironmentSanitizer::isSensitive);
    return builder;
  }

  static boolean isSensitive(String name) {
    String normalized = String.valueOf(name).toUpperCase(Locale.ROOT);
    if (SENSITIVE_NAMES.contains(normalized)) return true;
    return normalized.startsWith("AI_RUNTIME_")
        && (normalized.endsWith("_KEY")
            || normalized.endsWith("_TOKEN")
            || normalized.endsWith("_SECRET")
            || normalized.endsWith("_PASSWORD"));
  }
}
