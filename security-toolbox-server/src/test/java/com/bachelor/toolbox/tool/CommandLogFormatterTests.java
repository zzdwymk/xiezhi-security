package com.bachelor.toolbox.tool;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.Test;

class CommandLogFormatterTests {
  @Test
  void formatsArgumentsAndKeepsNmapPortFlagVisible() {
    String rendered =
        CommandLogFormatter.format(
            List.of("C:\\Program Files\\Nmap\\nmap.exe", "-sT", "-p", "80,443", "127.0.0.1"));

    assertTrue(rendered.contains("\"C:\\\\Program Files\\\\Nmap\\\\nmap.exe\""));
    assertTrue(rendered.contains("-p 80,443"));
  }

  @Test
  void redactsSeparatedAndAssignedSecrets() {
    String rendered =
        CommandLogFormatter.format(
            List.of("tool", "--api-key", "top-secret", "--token=abc123", "--password", "hunter2"));

    assertFalse(rendered.contains("top-secret"));
    assertFalse(rendered.contains("abc123"));
    assertFalse(rendered.contains("hunter2"));
    assertTrue(rendered.contains("--api-key [REDACTED]"));
    assertTrue(rendered.contains("--token=[REDACTED]"));
  }

  @Test
  void removesUriCredentialsAndSensitiveQueryValues() {
    String rendered =
        CommandLogFormatter.format(
            List.of("tool", "https://user:pass@example.com/path?api_key=secret&mode=safe"));

    assertFalse(rendered.contains("user:pass"));
    assertFalse(rendered.contains("secret"));
    assertTrue(rendered.contains("api_key=[REDACTED]"));
    assertTrue(rendered.contains("mode=safe"));
  }
}
