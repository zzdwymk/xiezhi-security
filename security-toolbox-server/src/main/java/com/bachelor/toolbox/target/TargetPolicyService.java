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

  /**
   * 在授权目标基址上解析一条已发现路径，返回可请求的 URI。仍只校验 host+端口（授权粒度为 host:端口，
   * 路径不参与授权校验）。path 可为相对路径（/Less-2/?id=1）或同主机的完整 URL；为空或 "/" 时退回基址。
   */
  public URI validatedHttpUri(AuthorizedTarget target, String path) {
    URI base = validatedHttpUri(target);
    if (path == null || path.isBlank() || "/".equals(path.trim())) {
      return base;
    }
    String p = path.trim();
    if (p.startsWith("http://") || p.startsWith("https://")) {
      URI abs;
      try {
        abs = URI.create(p);
      } catch (IllegalArgumentException ex) {
        throw new ApiException("路径 URL 格式不正确");
      }
      String host = abs.getHost();
      if (host == null || !host.equalsIgnoreCase(base.getHost())) {
        throw new ApiException("路径主机与授权目标不一致");
      }
      int port =
          abs.getPort() > 0
              ? abs.getPort()
              : ("https".equalsIgnoreCase(abs.getScheme()) ? 443 : 80);
      validateAuthorizedPort(target, port);
      return abs;
    }
    if (!p.startsWith("/")) {
      p = "/" + p;
    }
    String rawPath = p;
    String rawQuery = null;
    int q = p.indexOf('?');
    if (q >= 0) {
      rawPath = p.substring(0, q);
      rawQuery = p.substring(q + 1);
    }
    try {
      return new URI(base.getScheme(), null, base.getHost(), base.getPort(), rawPath, rawQuery, null);
    } catch (Exception ex) {
      throw new ApiException("目标路径格式不正确");
    }
  }

  /**
   * 复核一条“服务端预解析”的 Web 基址是否仍属于当前授权目标。
   *
   * <p>Round 398：{@code __resolvedWebBases} 只是任务参数里的缓存信息，不是授权凭证。
   * 定时计划/重试/回归复测可能把旧的基址带入新任务，目标端口或地址也可能在期间被修改。
   * 因此工具在真正发请求前，必须像 SQL 注入工具那样重新核对最终 scheme、host、port。
   */
  public URI validatedResolvedHttpUri(AuthorizedTarget target, URI candidate) {
    if (candidate == null) {
      throw new ApiException("Web 基址不能为空");
    }
    String host = validatedHost(target);
    if (!"http".equalsIgnoreCase(candidate.getScheme())
        && !"https".equalsIgnoreCase(candidate.getScheme())) {
      throw new ApiException("Web 基址仅支持 http 或 https");
    }
    if (candidate.getHost() == null || !candidate.getHost().equalsIgnoreCase(host)) {
      throw new ApiException("Web 基址主机与授权目标不一致");
    }
    if (candidate.getRawUserInfo() != null || candidate.getRawFragment() != null) {
      throw new ApiException("Web 基址不允许包含用户信息或片段");
    }
    int port =
        candidate.getPort() >= 0
            ? candidate.getPort()
            : ("https".equalsIgnoreCase(candidate.getScheme()) ? 443 : 80);
    validateAuthorizedPort(target, port);
    return candidate;
  }

  public void validateAuthorizedPort(AuthorizedTarget target, int port) {
    if (port < PortRangeParser.MIN_PORT || port > PortRangeParser.MAX_PORT) {
      throw new ApiException("目标端口必须在 1-65535 范围内");
    }
    // Round 373：用 containsPort 做成员判断，避免把 1-65535 这类紧凑授权串展开成 65,535 个 Integer。
    // 该方法在每条链接解析、每次探测/登记/任务创建时都会执行，展开即构成「全端口 × 请求数」的分配放大。
    if (!portRangeParser.containsPort(target.getAllowedPorts(), port)) {
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
