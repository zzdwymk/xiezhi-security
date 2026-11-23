package com.bachelor.toolbox.recon;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import com.bachelor.toolbox.asset.DiscoveredPathService;
import com.bachelor.toolbox.project.AssessmentProjectService;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.AuthorizedTargetRepository;
import com.bachelor.toolbox.target.TargetService;
import com.bachelor.toolbox.traffic.TrafficPacketRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.lang.reflect.Method;
import org.junit.jupiter.api.Test;

/**
 * 第355轮：爬虫链接解析必须同时校验授权端口。
 *
 * <p>{@code resolveLink} 只校验 host 相同，不校验端口；而爬虫在
 * {@code DiscoveredPathService.record} 做端口兜底**之前**就已经用 {@code probePath}/
 * {@code fetchBody} 发请求。于是页面里一个指向同主机「未授权端口」的链接
 * （如 {@code http://192.168.222.157:6379/}）会被真实访问，之后才被静默丢弃。
 */
class ReconCrawlLinkPortScopeTests {

  private static ReconService service() {
    return new ReconService(
        mock(ReconResultRepository.class),
        mock(AssessmentProjectService.class),
        mock(AuthorizedTargetRepository.class),
        mock(TargetService.class),
        new ObjectMapper(),
        mock(IcpBrowserCaptureStore.class),
        mock(DiscoveredPathService.class),
        mock(TrafficPacketRepository.class),
        mock(SubdomainDictionaryService.class),
        mock(PathDictionaryService.class),
        new com.bachelor.toolbox.target.PortRangeParser());
  }

  private static AuthorizedTarget target(String allowedPorts) {
    AuthorizedTarget target = new AuthorizedTarget();
    target.setId(1L);
    target.setTargetValue("http://192.168.222.157/");
    target.setAllowedPorts(allowedPorts);
    target.setEnabled(true);
    return target;
  }

  @Test
  void linkToUnauthorizedPortOnSameHostIsRejected() throws Exception {
    Method resolve =
        ReconService.class.getDeclaredMethod(
            "resolveLink", String.class, String.class, AuthorizedTarget.class);
    resolve.setAccessible(true);
    ReconService service = service();

    Object samePort = resolve.invoke(service, "http://192.168.222.157/", "/admin", target("80"));
    Object otherPort =
        resolve.invoke(
            service,
            "http://192.168.222.157/",
            "http://192.168.222.157:6379/",
            target("80"));
    Object otherHost =
        resolve.invoke(
            service, "http://192.168.222.157/", "http://evil.example.com/", target("80"));

    assertThat(samePort).as("授权端口内的链接应保留").isEqualTo("http://192.168.222.157/admin");
    assertThat(otherPort)
        .as("同 host 但未授权端口的链接必须在发请求前丢弃（不能靠 record 事后兜底）")
        .isNull();
    assertThat(otherHost).as("跨 host 链接继续拒绝").isNull();
  }
}
