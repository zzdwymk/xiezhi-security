package com.bachelor.toolbox.recon;

import jakarta.validation.constraints.NotNull;
import java.util.List;

public record ReconRequest(
    @NotNull(message = "目标 ID 不能为空") Long targetId,
    Boolean includeHttp,
    Boolean includeTls,
    Boolean enumerateSubdomains,
    List<String> subdomainWords,
    Boolean activeNetworkProbe,
    String mode,
    Boolean includeSameSubnet) {
  public boolean activeMode() {
    return "ACTIVE".equalsIgnoreCase(mode) || Boolean.TRUE.equals(activeNetworkProbe);
  }

  public boolean sameSubnetRequested() {
    return Boolean.TRUE.equals(includeSameSubnet) && activeMode();
  }
}
