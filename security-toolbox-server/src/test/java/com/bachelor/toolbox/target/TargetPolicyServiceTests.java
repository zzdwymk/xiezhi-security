package com.bachelor.toolbox.target;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.bachelor.toolbox.common.ApiException;
import org.junit.jupiter.api.Test;

/**
 * 第329轮：目标主机 SSRF 边界的回归测试。
 *
 * <p>默认安全策略（allowPublicTargets=false）下：回环/局域网允许；链路本地（169.254，云元数据）、
 * 任意地址（0.0.0.0）、公网地址、域名（可被 DNS 重绑定）拒绝。此前没有专项测试覆盖这些判断。
 */
class TargetPolicyServiceTests {

  private static TargetPolicyService service(boolean allowPublic) {
    return new TargetPolicyService(allowPublic, new PortRangeParser());
  }

  private static AuthorizedTarget target(String value, String ports) {
    AuthorizedTarget target = new AuthorizedTarget();
    target.setTargetValue(value);
    target.setAllowedPorts(ports);
    target.setEnabled(true);
    return target;
  }

  @Test
  void loopbackAndPrivateAddressesAreAllowedByDefault() {
    assertThat(service(false).validatedHost(target("http://127.0.0.1/", "80"))).isEqualTo("127.0.0.1");
    assertThat(service(false).validatedHost(target("http://192.168.222.157/", "80"))).isEqualTo("192.168.222.157");
    assertThat(service(false).validatedHost(target("http://10.1.2.3/", "80"))).isEqualTo("10.1.2.3");
  }

  @Test
  void linkLocalMetadataAddressIsRejected() {
    assertThatThrownBy(() -> service(false).validatedHost(target("http://169.254.169.254/", "80")))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("仅允许");
  }

  @Test
  void anyLocalAddressIsRejected() {
    assertThatThrownBy(() -> service(false).validatedHost(target("http://0.0.0.0/", "80")))
        .isInstanceOf(ApiException.class);
  }

  @Test
  void publicAddressIsRejectedWhenPublicTargetsDisabled() {
    assertThatThrownBy(() -> service(false).validatedHost(target("http://8.8.8.8/", "80")))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("仅允许");
  }

  @Test
  void hostnameIsRejectedWhenPublicTargetsDisabled() {
    assertThatThrownBy(() -> service(false).validatedHost(target("http://example.com/", "80")))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("域名");
  }

  @Test
  void unauthorizedPortIsRejected() {
    TargetPolicyService service = service(false);
    AuthorizedTarget target = target("http://192.168.222.157/", "80,443");
    assertThatThrownBy(() -> service.validateAuthorizedPort(target, 8080))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("不在授权端口范围内");
    service.validateAuthorizedPort(target, 443);
  }
}
