package com.bachelor.toolbox.target;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.asset.DiscoveredPathService;
import com.bachelor.toolbox.common.ApiException;
import java.net.URI;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class WebTargetResolverTests {
  private final TargetPolicyService policy = mock(TargetPolicyService.class);
  private final DiscoveredPathService discoveredPaths = mock(DiscoveredPathService.class);
  private final PortRangeParser portRangeParser = new PortRangeParser();
  private final WebTargetResolver resolver =
      new WebTargetResolver(policy, portRangeParser, discoveredPaths);

  private AuthorizedTarget target(String value, String type, String allowedPorts) {
    AuthorizedTarget t = new AuthorizedTarget();
    t.setTargetValue(value);
    t.setTargetType(type);
    t.setAllowedPorts(allowedPorts);
    t.setEnabled(true);
    return t;
  }

  @Test
  void readsResolvedBasesFromParameters() {
    Map<String, Object> parameters =
        Map.of(
            WebTargetResolver.PARAM_RESOLVED_BASES,
            List.of("https://127.0.0.1:8443", "http://10.0.0.5:8080", "not a valid uri"));

    List<URI> bases = WebTargetResolver.basesFromParameters(parameters);

    assertThat(bases)
        .containsExactly(
            URI.create("https://127.0.0.1:8443"), URI.create("http://10.0.0.5:8080"));
  }

  @Test
  void joinsBaseWithPath() {
    assertThat(resolver.join(URI.create("https://10.0.0.5:8443"), "/login"))
        .isEqualTo(URI.create("https://10.0.0.5:8443/login"));
    assertThat(resolver.join(URI.create("https://10.0.0.5:8443"), null))
        .isEqualTo(URI.create("https://10.0.0.5:8443"));
    assertThat(resolver.join(URI.create("https://10.0.0.5:8443"), "https://10.0.0.5:8443/app?id=1"))
        .isEqualTo(URI.create("https://10.0.0.5:8443/app?id=1"));
  }

  @Test
  void explicitUrlTargetIsUsedWithoutProbe() throws Exception {
    AuthorizedTarget target = target("https://10.0.0.5:8443/app", "URL", "80,443,8443");
    when(policy.validatedHttpUri(target)).thenReturn(URI.create("https://10.0.0.5:8443/app"));

    List<URI> bases = resolver.resolve(target, List.of());

    assertThat(bases).containsExactly(URI.create("https://10.0.0.5:8443/app"));
  }

  @Test
  void bareHostWithNonWebServiceThrowsWithGuidance() {
    AuthorizedTarget target = target("10.0.0.5", "IP", "22");
    when(policy.validatedHost(target)).thenReturn("10.0.0.5");

    assertThatThrownBy(() -> resolver.resolve(target, List.of()))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("无法确认目标");
  }

  @Test
  void recordAssetsRecordsEachBase() {
    AuthorizedTarget target = target("10.0.0.5", "IP", "80");
    List<URI> bases = List.of(URI.create("http://10.0.0.5"), URI.create("https://10.0.0.5/"));

    resolver.recordAssets(target, 1L, bases);

    org.mockito.Mockito.verify(discoveredPaths)
        .record(target, 1L, "http://10.0.0.5", "TARGET_RESOLVER", 0, 0L, "由目标地址解析确认可达");
    org.mockito.Mockito.verify(discoveredPaths)
        .record(target, 1L, "https://10.0.0.5/", "TARGET_RESOLVER", 0, 0L, "由目标地址解析确认可达");
  }

  @Test
  void tryResolveReturnsEmptyWhenProbingUnavailable() {
    AuthorizedTarget target = target("10.0.0.5", "IP", "80");
    when(policy.validatedHost(target)).thenReturn("10.0.0.5");

    assertThat(resolver.tryResolve(target)).isEmpty();
  }
}