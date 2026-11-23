package com.bachelor.toolbox.target;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.common.ApiException;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * 第374轮：宽授权范围下默认 Web 端口（80/443）永远不被探测。
 *
 * <p>{@code probeCandidates} 先把 {@code allowedPorts} 完整展开、再把 80/443 追加在末尾，而
 * {@code probeAll} 只取前 {@code MAX_RESOLVED_BASES*2 = 16} 个候选（8 个端口 × http/https）。
 * 因此当授权范围是 {@code 1-65535} 这类宽范围时，候选被端口 1..8 占满，**80/443 从未被探测**，
 * 裸 IP 目标的 Web 基址解析必然失败（"无法确认可访问的 Web 服务地址"），web 类工具全部跑不起来。
 *
 * <p>同时该展开本身是 65,535 个 Integer 的分配（R373 同类问题的残留点）。
 */
@DisplayName("宽授权范围下默认 Web 端口必须被探测（第374轮）")
class WebTargetResolverWideRangePortTests {
  private static final String HOST = "192.168.222.155";
  private final HttpClient client = mock(HttpClient.class);
  private final PortRangeParser ports = new PortRangeParser();
  private final WebTargetResolver resolver =
      new WebTargetResolver(new TargetPolicyService(false, ports), ports, null, client);
  private final List<URI> requested = Collections.synchronizedList(new ArrayList<>());

  private AuthorizedTarget target(String allowedPorts) {
    AuthorizedTarget target = new AuthorizedTarget();
    target.setId(374L);
    target.setTargetValue(HOST);
    target.setTargetType("IP");
    target.setAllowedPorts(allowedPorts);
    target.setEnabled(true);
    return target;
  }

  private void recordRequests() throws Exception {
    when(client.send(any(HttpRequest.class),
        org.mockito.ArgumentMatchers.<HttpResponse.BodyHandler<Void>>any()))
        .thenAnswer(invocation -> {
          HttpRequest request = invocation.getArgument(0);
          requested.add(request.uri());
          throw new IOException("controlled unreachable endpoint");
        });
  }

  @Test
  @DisplayName("授权 1-65535 时，探测必须包含 80 与 443")
  void wideAuthorizedRangeStillProbesDefaultWebPorts() throws Exception {
    recordRequests();
    assertThatThrownBy(() -> resolver.resolve(target("1-65535"), List.of()))
        .isInstanceOf(ApiException.class);

    assertThat(requested).isNotEmpty();
    assertThat(requested.stream().anyMatch(u -> effectivePort(u) == 80))
        .as("宽授权范围下 80 必须被探测，实际探测：%s", requested)
        .isTrue();
    assertThat(requested.stream().anyMatch(u -> effectivePort(u) == 443))
        .as("宽授权范围下 443 必须被探测，实际探测：%s", requested)
        .isTrue();
  }

  @Test
  @DisplayName("探测候选必须保持有界（不因宽范围无限放大）")
  void candidateCountStaysBounded() throws Exception {
    recordRequests();
    assertThatThrownBy(() -> resolver.resolve(target("1-65535"), List.of()))
        .isInstanceOf(ApiException.class);
    assertThat(requested.size()).as("候选数量必须有界").isLessThanOrEqualTo(20);
  }

  @Test
  @DisplayName("firstPorts 按输入顺序取前 N 个端口且不展开全段")
  void firstPortsIsBoundedAndOrdered() {
    PortRangeParser parser = new PortRangeParser();
    assertThat(parser.firstPorts("1-65535", 8)).containsExactly(1, 2, 3, 4, 5, 6, 7, 8);
    assertThat(parser.firstPorts("80,443,8080", 5)).containsExactly(80, 443, 8080);
    assertThat(parser.firstPorts("8000-8002,443", 2)).containsExactly(8000, 8001);
    assertThatThrownBy(() -> parser.firstPorts("80,bad", 5)).isInstanceOf(ApiException.class);
    // 与 parse(spec, maxPorts) 一致：非法限额属于编程错误，抛 IllegalArgumentException。
    assertThatThrownBy(() -> parser.firstPorts("1-65535", 0))
        .isInstanceOf(IllegalArgumentException.class);
    assertThat(parser.firstPorts("  80  ", 1)).containsExactly(80);
  }

  private static int effectivePort(URI uri) {
    if (uri.getPort() > 0) return uri.getPort();
    return "https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80;
  }
}
