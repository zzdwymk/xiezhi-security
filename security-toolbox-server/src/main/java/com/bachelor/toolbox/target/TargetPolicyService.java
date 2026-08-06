package com.bachelor.toolbox.target;

import com.bachelor.toolbox.common.ApiException;
import java.net.InetAddress;
import java.net.URI;
import java.util.Arrays;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class TargetPolicyService {
  private final boolean allowPublicTargets;
  private final PortRangeParser portRangeParser;

  public TargetPolicyService(
      @Value("${toolbox.execution.allow-public-targets:false}") boolean allowPublicTargets,
      PortRangeParser portRangeParser) {
    this.allowPublicTargets = allowPublicTargets;
    this.portRangeParser = portRangeParser;
  }

  public String validatedHost(AuthorizedTarget target) {
    if (!target.isEnabled()) {
      throw new ApiException("目标已停用");
    }
    String host = extractHost(target.getTargetValue());
    try {
      if (!allowPublicTargets && !isLiteralAddress(host) && !"localhost".equalsIgnoreCase(host)) {
        throw new ApiException("默认安全策略要求使用局域网 IP、回环 IP 或 localhost，避免域名解析变化导致越权探测");
      }
      InetAddress[] addresses = InetAddress.getAllByName(host);
      boolean safe = Arrays.stream(addresses).allMatch(this::isPrivateAddress);
      if (!allowPublicTargets && !safe) {
        throw new ApiException("当前安全策略仅允许回环地址、局域网地址和自建靶场；如确有书面授权，可由管理员显式开启公网目标");
      }
      return host;
    } catch (ApiException ex) {
      throw ex;
    } catch (Exception ex) {
      throw new ApiException("无法解析授权目标: " + host);
    }
  }

  public URI validatedHttpUri(AuthorizedTarget target) {
    validatedHost(target);
    try {
      URI uri = URI.create(target.getTargetValue());
      if (uri.getScheme() == null) {
        uri = URI.create("http://" + target.getTargetValue());
      }
      if (!"http".equalsIgnoreCase(uri.getScheme()) && !"https".equalsIgnoreCase(uri.getScheme())) {
        throw new ApiException("HTTP 检查仅支持 http 或 https 目标");
      }
      int port =
          uri.getPort() > 0
              ? uri.getPort()
              : ("https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80);
      validateAuthorizedPort(target, port);
      return uri;
    } catch (IllegalArgumentException ex) {
      throw new ApiException("目标 URL 格式不正确");
    }
  }

  public void validateAuthorizedPort(AuthorizedTarget target, int port) {
    if (port < PortRangeParser.MIN_PORT || port > PortRangeParser.MAX_PORT) {
      throw new ApiException("目标端口必须在 1-65535 范围内");
    }
    if (!portRangeParser.parse(target.getAllowedPorts()).contains(port)) {
      throw new ApiException("目标端口 " + port + " 不在授权端口范围内");
    }
  }

  private String extractHost(String value) {
    try {
      URI uri = URI.create(value.contains("://") ? value : "//" + value);
      String host = uri.getHost();
      if (host == null || host.isBlank()) {
        throw new ApiException("无法从目标中识别主机名或 IP");
      }
      return host;
    } catch (IllegalArgumentException ex) {
      throw new ApiException("目标地址格式不正确");
    }
  }

  private boolean isPrivateAddress(InetAddress address) {
    if (address.isAnyLocalAddress() || address.isLinkLocalAddress() || address.isMulticastAddress())
      return false;
    if (address.isLoopbackAddress() || address.isSiteLocalAddress()) return true;
    byte[] bytes = address.getAddress();
    return bytes.length == 16 && (bytes[0] & 0xfe) == 0xfc;
  }

  private boolean isLiteralAddress(String host) {
    return host.contains(":") || host.matches("^[0-9]{1,3}(\\.[0-9]{1,3}){3}$");
  }
}
