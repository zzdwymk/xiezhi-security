package com.bachelor.toolbox.tool;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import com.bachelor.toolbox.target.TargetPolicyService;
import java.net.URI;
import java.net.http.HttpHeaders;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class HttpSecurityCheckToolTests {
  private final HttpSecurityCheckTool tool =
      new HttpSecurityCheckTool(mock(TargetPolicyService.class));

  @Test
  void detectsMissingAttributesWithoutExposingCookieValue() {
    HttpHeaders headers =
        headers(
            Map.of("Set-Cookie", List.of("JSESSIONID=super-secret-value; Path=/; SameSite=Lax")));

    List<FindingDraft> findings = tool.analyzeCookies(URI.create("https://127.0.0.1"), headers);

    assertThat(findings).hasSize(1);
    assertThat(findings.get(0).title()).contains("JSESSIONID");
    assertThat(findings.get(0).evidence())
        .contains("Secure", "HttpOnly")
        .doesNotContain("super-secret-value");
  }

  @Test
  void acceptsCompactCookieAttributeSyntax() {
    HttpHeaders headers =
        headers(Map.of("Set-Cookie", List.of("auth_token=value;Secure;HttpOnly;SameSite=Strict")));

    assertThat(tool.analyzeCookies(URI.create("https://127.0.0.1"), headers)).isEmpty();
  }

  @Test
  void detectsReflectedCredentialedCorsOrigin() {
    HttpHeaders headers =
        headers(
            Map.of(
                "Access-Control-Allow-Origin", List.of("https://security-toolbox.invalid"),
                "Access-Control-Allow-Credentials", List.of("true")));

    List<FindingDraft> findings = tool.analyzeCors(headers, "https://security-toolbox.invalid");

    assertThat(findings)
        .singleElement()
        .satisfies(
            finding -> {
              assertThat(finding.severity()).isEqualTo("HIGH");
              assertThat(finding.title()).contains("CORS");
            });
  }

  @Test
  void detectsDangerousAdvertisedMethods() {
    HttpHeaders headers = headers(Map.of("Allow", List.of("GET, POST, TRACE, CONNECT")));

    List<FindingDraft> findings = tool.analyzeMethods(headers);

    assertThat(findings)
        .singleElement()
        .satisfies(
            finding -> {
              assertThat(finding.severity()).isEqualTo("HIGH");
              assertThat(finding.evidence()).contains("TRACE", "CONNECT");
            });
  }

  @Test
  void detectsTechnologyDisclosureHeaders() {
    HttpHeaders headers =
        headers(
            Map.of(
                "Server", List.of("nginx/1.24.0"),
                "X-Powered-By", List.of("Express")));

    List<FindingDraft> findings = tool.analyzeDisclosure(headers);

    assertThat(findings)
        .singleElement()
        .satisfies(finding -> assertThat(finding.evidence()).contains("nginx/1.24.0", "Express"));
  }

  private HttpHeaders headers(Map<String, List<String>> values) {
    return HttpHeaders.of(values, (name, value) -> true);
  }
}
