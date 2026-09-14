package com.bachelor.toolbox.traffic;

import com.bachelor.toolbox.asset.DiscoveredPathService;
import com.bachelor.toolbox.project.ProjectTarget;
import com.bachelor.toolbox.project.ProjectTargetRepository;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.AuthorizedTargetRepository;
import java.net.URI;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * 把流量代理抓包结果自动沉淀为项目 Web 资产（discovered_paths），使资产拓扑无需手动执行“信息收集”即可看到抓到的
 * host/路径。仅当抓包 host 与某个授权目标一致、端口在授权范围内时才入库（复用 {@link DiscoveredPathService}
 * 的 host+端口纵深防御过滤，越界流量静默丢弃）。
 */
@Service
public class TrafficAssetSyncService {
  private static final Logger LOGGER = LoggerFactory.getLogger(TrafficAssetSyncService.class);
  private static final String SOURCE = "PROXY";
  private static final String NOTE = "代理流量自动入库";

  private final AuthorizedTargetRepository targets;
  private final ProjectTargetRepository projectTargets;
  private final TrafficPacketRepository packets;
  private final DiscoveredPathService discoveredPaths;

  public TrafficAssetSyncService(
      AuthorizedTargetRepository targets,
      ProjectTargetRepository projectTargets,
      TrafficPacketRepository packets,
      DiscoveredPathService discoveredPaths) {
    this.targets = targets;
    this.projectTargets = projectTargets;
    this.packets = packets;
    this.discoveredPaths = discoveredPaths;
  }

  /**
   * 扫描全部授权目标，把已抓包的同 host 路径同步进各关联项目的资产。返回新增（去重后）条数。 幂等：重复调用不会产生重复资产。
   */
  public int syncAll() {
    int recorded = 0;
    for (AuthorizedTarget target : targets.findAll()) {
      recorded += syncTarget(target);
    }
    return recorded;
  }

  /** 单条抓包到达时的增量同步：仅当会话绑定了授权目标（targetId>0）时生效。 */
  public void ingest(TrafficPacket packet) {
    if (packet == null || packet.getTargetId() == null || packet.getTargetId() <= 0) {
      return;
    }
    targets
        .findById(packet.getTargetId())
        .ifPresent(
            target ->
                recordEndpoint(
                    target,
                    packet.getScheme(),
                    packet.getHost(),
                    packet.getPort(),
                    packet.getPath(),
                    packet.getStatusCode(),
                    packet.getResponseBytes()));
  }

  private int syncTarget(AuthorizedTarget target) {
    String host = hostOf(target.getTargetValue());
    if (host == null || host.isBlank()) {
      return 0;
    }
    List<ProjectTarget> links = projectTargets.findByTargetId(target.getId());
    if (links.isEmpty()) {
      return 0;
    }
    int recorded = 0;
    try {
      for (Object[] row : packets.findDistinctEndpointsByHost(host)) {
        String scheme = row[0] == null ? "http" : String.valueOf(row[0]);
        String rowHost = row[1] == null ? host : String.valueOf(row[1]);
        Integer port = row[2] == null ? null : ((Number) row[2]).intValue();
        String path = row[3] == null ? "/" : String.valueOf(row[3]);
        recorded += recordEndpoint(target, scheme, rowHost, port, path, null, null);
      }
    } catch (RuntimeException ex) {
      LOGGER.debug("代理流量资产同步失败 target={} host={} : {}", target.getId(), host, ex.getMessage());
    }
    return recorded;
  }

  private int recordEndpoint(
      AuthorizedTarget target,
      String scheme,
      String host,
      Integer port,
      String path,
      Integer statusCode,
      Long responseBytes) {
    if (host == null || host.isBlank()) {
      return 0;
    }
    String normalizedScheme = scheme == null || scheme.isBlank() ? "http" : scheme;
    String normalizedPath = path == null || path.isBlank() ? "/" : path;
    if (!normalizedPath.startsWith("/")) {
      normalizedPath = "/" + normalizedPath;
    }
    boolean defaultPort =
        ("http".equalsIgnoreCase(normalizedScheme) && port != null && port == 80)
            || ("https".equalsIgnoreCase(normalizedScheme) && port != null && port == 443);
    String url =
        normalizedScheme
            + "://"
            + host
            + (port != null && port > 0 && !defaultPort ? ":" + port : "")
            + normalizedPath;
    int recorded = 0;
    for (ProjectTarget link : projectTargets.findByTargetId(target.getId())) {
      try {
        if (discoveredPaths.record(
            target, link.getProjectId(), url, SOURCE, statusCode, responseBytes, NOTE)) {
          recorded++;
        }
      } catch (RuntimeException ex) {
        LOGGER.debug(
            "代理流量资产入库失败 target={} project={} url={} : {}",
            target.getId(),
            link.getProjectId(),
            url,
            ex.getMessage());
      }
    }
    return recorded;
  }

  private String hostOf(String targetValue) {
    if (targetValue == null || targetValue.isBlank()) {
      return null;
    }
    try {
      URI uri = URI.create(targetValue.contains("://") ? targetValue : "//" + targetValue);
      return uri.getHost();
    } catch (RuntimeException ex) {
      return null;
    }
  }
}
