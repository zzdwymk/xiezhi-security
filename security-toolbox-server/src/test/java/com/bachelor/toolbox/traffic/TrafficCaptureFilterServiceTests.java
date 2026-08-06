package com.bachelor.toolbox.traffic;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.audit.AuditService;
import java.util.List;
import org.junit.jupiter.api.Test;

class TrafficCaptureFilterServiceTests {
  private final TrafficCaptureFilterRepository repository =
      mock(TrafficCaptureFilterRepository.class);
  private final TrafficCaptureFilterService service =
      new TrafficCaptureFilterService(repository, mock(AuditService.class));

  @Test
  void blacklistDomainMatchesTheDomainAndItsSubdomains() {
    when(repository.findAllByOrderByCreatedAtAsc())
        .thenReturn(List.of(rule("BLACKLIST", "DOMAIN", "example.com")));
    service.reload();

    assertTrue(service.shouldExclude(capture("example.com", "/")));
    assertTrue(service.shouldExclude(capture("api.example.com", "/v1")));
    assertFalse(service.shouldExclude(capture("example.org", "/")));
  }

  @Test
  void whitelistAllowsOnlyMatchesAndBlacklistStillWins() {
    when(repository.findAllByOrderByCreatedAtAsc())
        .thenReturn(
            List.of(rule("WHITELIST", "URL", "/api/"), rule("BLACKLIST", "KEYWORD", "tracking")));
    service.reload();

    assertFalse(service.shouldExclude(capture("example.com", "/api/users")));
    assertTrue(service.shouldExclude(capture("example.com", "/assets/app.js")));
    assertTrue(service.shouldExclude(capture("example.com", "/api/tracking")));
  }

  @Test
  void keywordChecksHeadersAndBodiesCaseInsensitively() {
    when(repository.findAllByOrderByCreatedAtAsc())
        .thenReturn(List.of(rule("BLACKLIST", "KEYWORD", "analytics-token")));
    service.reload();

    LocalTrafficProxy.Capture capture =
        new LocalTrafficProxy.Capture(
            "HTTPS",
            "POST",
            "https",
            "example.com",
            443,
            "/collect",
            200,
            "Content-Type: application/json",
            "{}",
            "X-Trace: ANALYTICS-TOKEN",
            "ok",
            2,
            2,
            10,
            "CAPTURED",
            "application/json",
            null);
    assertTrue(service.shouldExclude(capture));
  }

  private TrafficCaptureFilter rule(String listType, String type, String pattern) {
    TrafficCaptureFilter rule = new TrafficCaptureFilter();
    rule.setListType(listType);
    rule.setType(type);
    rule.setPattern(pattern);
    rule.setEnabled(true);
    return rule;
  }

  private LocalTrafficProxy.Capture capture(String host, String path) {
    return new LocalTrafficProxy.Capture(
        "HTTPS",
        "GET",
        "https",
        host,
        443,
        path,
        200,
        "Accept: */*",
        "",
        "Content-Type: text/plain",
        "ok",
        0,
        2,
        10,
        "CAPTURED",
        "text/plain",
        null);
  }
}
