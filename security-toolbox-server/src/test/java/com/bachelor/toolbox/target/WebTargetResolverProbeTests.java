package com.bachelor.toolbox.target;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpConnectTimeoutException;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.ssl.SSLException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class WebTargetResolverProbeTests {
  private static final String HOST = "192.168.136.132";
  private final HttpClient client = mock(HttpClient.class);
  private final PortRangeParser ports = new PortRangeParser();
  private final WebTargetResolver resolver = new WebTargetResolver(
      new TargetPolicyService(false, ports), ports, null, client);
  private final Map<String, AtomicInteger> calls = new ConcurrentHashMap<>();
  private final List<HttpRequest> requests = Collections.synchronizedList(new ArrayList<>());

  @BeforeEach
  void failUnexpectedRequestsWithoutOpeningNetworkConnections() throws Exception {
    when(client.send(any(HttpRequest.class), org.mockito.ArgumentMatchers.<HttpResponse.BodyHandler<Void>>any()))
        .thenAnswer(invocation -> { throw new IOException("controlled non-web endpoint"); });
  }

  private AuthorizedTarget target(String allowedPorts) {
    AuthorizedTarget target = new AuthorizedTarget();
    target.setId(307L);
    target.setTargetValue(HOST);
    target.setTargetType("IP");
    target.setAllowedPorts(allowedPorts);
    target.setEnabled(true);
    return target;
  }

  @SuppressWarnings("unchecked")
  private HttpResponse<Void> response(int status) {
    HttpResponse<Void> response = mock(HttpResponse.class);
    when(response.statusCode()).thenReturn(status);
    return response;
  }

  private int record(HttpRequest request) {
    requests.add(request);
    return calls.computeIfAbsent(request.uri().toString(), ignored -> new AtomicInteger()).incrementAndGet();
  }

  @Test
  void retriesAColdConnectTimeoutOnceAndKeepsOnlyTheAuthorizedBase() throws Exception {
    when(client.send(any(HttpRequest.class), org.mockito.ArgumentMatchers.<HttpResponse.BodyHandler<Void>>any()))
        .thenAnswer(invocation -> {
          HttpRequest request = invocation.getArgument(0);
          int attempt = record(request);
          if ("https".equals(request.uri().getScheme())) throw new SSLException("plain HTTP endpoint");
          if (attempt == 1) throw new HttpConnectTimeoutException("controlled cold connection");
          return response(200);
        });

    assertThat(resolver.tryResolve(target("80"))).containsExactly(URI.create("http://" + HOST + "/"));
    assertThat(calls.get("http://" + HOST + "/").get()).isEqualTo(2);
    assertThat(calls.get("https://" + HOST + ":80/").get()).isEqualTo(1);
    assertThat(requests).allSatisfy(request -> {
      assertThat(request.uri().getHost()).isEqualTo(HOST);
      assertThat(request.uri().getPort()).isIn(-1, 80);
      assertThat(request.timeout()).isPresent();
      assertThat(request.timeout().orElseThrow()).isLessThanOrEqualTo(Duration.ofSeconds(5));
    });
  }

  @Test
  void repeatedConnectTimeoutIsBoundedToTwoAttemptsPerCandidate() throws Exception {
    when(client.send(any(HttpRequest.class), org.mockito.ArgumentMatchers.<HttpResponse.BodyHandler<Void>>any()))
        .thenAnswer(invocation -> {
          record(invocation.getArgument(0));
          throw new HttpConnectTimeoutException("still unavailable");
        });
    assertThat(resolver.tryResolve(target("80"))).isEmpty();
    assertThat(calls).hasSize(2);
    assertThat(calls.values()).allSatisfy(count -> assertThat(count.get()).isEqualTo(2));
  }

  @ParameterizedTest
  @ValueSource(strings = {"tls", "response-timeout", "io"})
  void doesNotRetryProtocolResponseTimeoutOrOtherIoErrors(String failure) throws Exception {
    when(client.send(any(HttpRequest.class), org.mockito.ArgumentMatchers.<HttpResponse.BodyHandler<Void>>any()))
        .thenAnswer(invocation -> {
          record(invocation.getArgument(0));
          if ("tls".equals(failure)) throw new SSLException("controlled protocol mismatch");
          if ("response-timeout".equals(failure)) throw new HttpTimeoutException("response timed out");
          throw new IOException("controlled socket failure");
        });
    assertThat(resolver.tryResolve(target("80"))).isEmpty();
    assertThat(calls.values()).allSatisfy(count -> assertThat(count.get()).isEqualTo(1));
  }

  @Test
  void firstAttemptsForLaterCandidatesAreNotStarvedByRetries() throws Exception {
    when(client.send(any(HttpRequest.class), org.mockito.ArgumentMatchers.<HttpResponse.BodyHandler<Void>>any()))
        .thenAnswer(invocation -> {
          HttpRequest request = invocation.getArgument(0);
          record(request);
          if (request.uri().getPort() == 8080 && "http".equals(request.uri().getScheme())) return response(200);
          throw new HttpConnectTimeoutException("unavailable candidate");
        });
    assertThat(resolver.tryResolve(target("22,80,443,8000,8080")))
        .containsExactly(URI.create("http://" + HOST + ":8080/"));
    assertThat(calls.get("http://" + HOST + ":8080/").get()).isEqualTo(1);
  }

  @Test
  void totalBudgetStillEndsHungProbesAtSevenSeconds() throws Exception {
    when(client.send(any(HttpRequest.class), org.mockito.ArgumentMatchers.<HttpResponse.BodyHandler<Void>>any()))
        .thenAnswer(invocation -> {
          record(invocation.getArgument(0));
          Thread.sleep(10_000);
          return response(200);
        });
    long started = System.nanoTime();
    org.junit.jupiter.api.Assertions.assertTimeoutPreemptively(Duration.ofSeconds(8), () ->
        assertThat(resolver.tryResolve(target("80"))).isEmpty());
    assertThat(Duration.ofNanos(System.nanoTime() - started)).isLessThan(Duration.ofSeconds(8));
    assertThat(calls.values()).allSatisfy(count -> assertThat(count.get()).isEqualTo(1));
  }

  @Test
  void unavailableDiscoveredPortsOutsideAuthorizationAreNeverRequested() throws Exception {
    when(client.send(any(HttpRequest.class), org.mockito.ArgumentMatchers.<HttpResponse.BodyHandler<Void>>any()))
        .thenAnswer(invocation -> { record(invocation.getArgument(0)); return response(200); });
    assertThat(resolver.resolve(target("80"), List.of(Map.of("port", 80), Map.of("port", 8080))))
        .containsExactly(URI.create("http://" + HOST + "/"), URI.create("https://" + HOST + ":80/"));
    assertThat(requests).hasSize(2).allSatisfy(request -> assertThat(request.uri().getPort()).isIn(-1, 80));
  }

  @Test
  void productionClientNeverFollowsRedirects() {
    WebTargetResolver production = new WebTargetResolver(new TargetPolicyService(false, ports), ports, null);
    HttpClient productionClient = (HttpClient) org.springframework.test.util.ReflectionTestUtils
        .getField(production, "httpClient");
    assertThat(productionClient.followRedirects()).isEqualTo(HttpClient.Redirect.NEVER);
  }
}
