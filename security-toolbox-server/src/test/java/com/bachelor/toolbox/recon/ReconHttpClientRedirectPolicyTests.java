package com.bachelor.toolbox.recon;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.http.HttpClient;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

/**
 * 第356轮：recon 的全部 HTTP 客户端都必须禁用自动重定向。
 *
 * <p>自动跟随重定向意味着「请求已经发往重定向目标」——即使事后校验 host 也无法阻止越界出站
 * （历史 R~ 曾用 {@code Redirect.NORMAL} 跟随到内网/云元数据地址）。这里对
 * {@code passiveClient} / {@code activeClient} / {@code paramProbeClient} 做结构断言，防止后续
 * 改动重新打开该 SSRF 面。
 */
class ReconHttpClientRedirectPolicyTests {

  @Test
  void allReconClientsUseRedirectNever() {
    ReconService service =
        new ReconService(
            org.mockito.Mockito.mock(ReconResultRepository.class),
            org.mockito.Mockito.mock(com.bachelor.toolbox.project.AssessmentProjectService.class),
            org.mockito.Mockito.mock(com.bachelor.toolbox.target.AuthorizedTargetRepository.class),
            org.mockito.Mockito.mock(com.bachelor.toolbox.target.TargetService.class),
            new com.fasterxml.jackson.databind.ObjectMapper(),
            org.mockito.Mockito.mock(IcpBrowserCaptureStore.class),
            org.mockito.Mockito.mock(com.bachelor.toolbox.asset.DiscoveredPathService.class),
            org.mockito.Mockito.mock(com.bachelor.toolbox.traffic.TrafficPacketRepository.class),
            org.mockito.Mockito.mock(SubdomainDictionaryService.class),
            org.mockito.Mockito.mock(PathDictionaryService.class),
            new com.bachelor.toolbox.target.PortRangeParser());

    for (String field : List.of("passiveClient", "activeClient", "paramProbeClient")) {
      HttpClient client = (HttpClient) ReflectionTestUtils.getField(service, field);
      assertThat(client).as("%s 必须存在", field).isNotNull();
      assertThat(client.followRedirects())
          .as("%s 必须使用 Redirect.NEVER，避免越界出站", field)
          .isEqualTo(HttpClient.Redirect.NEVER);
    }
  }
}
