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
    Boolean includeSameSubnet,
    String pathDictionaryId,
    Integer pathConcurrency,
    Boolean fuseCrawlWithDirScan) {

  /**
   * 融合模式是否开启：爬虫与目录枚举共用一条迭代流水线（爬虫发现的目录前缀喂给字典扫描，
   * 字典命中的可达页面回灌爬虫队列）。仅当同时请求了 {@code crawlSite} 与 {@code enumeratePaths}
   * 且显式打开本开关时生效；否则两条流水线仍各自独立运行（保持历史行为）。
   */
  public boolean fuseEnabled() {
    return Boolean.TRUE.equals(fuseCrawlWithDirScan)
        && Boolean.TRUE.equals(crawlSite)
        && Boolean.TRUE.equals(enumeratePaths)
        && activeMode();
  }

  /** 兼容 14 参构造器（无融合开关，默认关闭融合）。 */
  public ReconRequest(
      Long targetId,
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
      Boolean includeSameSubnet,
      String pathDictionaryId,
      Integer pathConcurrency) {
    this(
        targetId,
        includeHttp,
        includeTls,
        enumerateSubdomains,
        subdomainWords,
        enumeratePaths,
        pathWords,
        crawlSite,
        aggregateProxyPaths,
        activeNetworkProbe,
        mode,
        includeSameSubnet,
        pathDictionaryId,
        pathConcurrency,
        false);
  }

  /** 兼容 12 参构造器（无显式字典 id 与并发字段）。 */
  public ReconRequest(
      Long targetId,
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
    this(
        targetId,
        includeHttp,
        includeTls,
        enumerateSubdomains,
        subdomainWords,
        enumeratePaths,
        pathWords,
        crawlSite,
        aggregateProxyPaths,
        activeNetworkProbe,
        mode,
        includeSameSubnet,
        null,
        null,
        false);
  }

  /** 兼容旧 8 参签名（无子路径发现字段）的构造器；新字段默认关闭。 */
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
        includeSameSubnet,
        null,
        null,
        false);
  }

  public boolean activeMode() {
    return "ACTIVE".equalsIgnoreCase(mode) || Boolean.TRUE.equals(activeNetworkProbe);
  }

  public boolean sameSubnetRequested() {
    return Boolean.TRUE.equals(includeSameSubnet) && activeMode();
  }
}
