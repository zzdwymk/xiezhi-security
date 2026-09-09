package com.bachelor.toolbox.recon;

import jakarta.validation.constraints.NotNull;
import java.util.List;

public record ReconRequest(
    @NotNull(message = "目标 ID 不能为空") Long targetId,
    Boolean includeHttp,
    Boolean includeTls,
    Boolean enumerateSubdomains,
    List<String> subdomainWords,
    Boolean enumeratePaths,
    List<String> pathWords,
    Boolean crawlSite,
    Boolean aggregateProxyPaths,
    Boolean activeNetworkProbe,
    String mode,
    Boolean includeSameSubnet) {

  /** 兼容旧签名（无子路径发现字段）的构造器；新字段默认关闭。 */
  public ReconRequest(
      Long targetId,
      Boolean includeHttp,
      Boolean includeTls,
      Boolean enumerateSubdomains,
      List<String> subdomainWords,
      Boolean activeNetworkProbe,
      String mode,
      Boolean includeSameSubnet) {
    this(
        targetId,
        includeHttp,
        includeTls,
        enumerateSubdomains,
        subdomainWords,
        false,
        null,
        false,
        false,
        activeNetworkProbe,
        mode,
        includeSameSubnet);
  }

  public boolean activeMode() {
    return "ACTIVE".equalsIgnoreCase(mode) || Boolean.TRUE.equals(activeNetworkProbe);
  }

  public boolean sameSubnetRequested() {
    return Boolean.TRUE.equals(includeSameSubnet) && activeMode();
  }
}
