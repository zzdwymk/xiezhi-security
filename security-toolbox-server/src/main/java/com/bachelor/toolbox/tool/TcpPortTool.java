package com.bachelor.toolbox.tool;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.PortRangeParser;
import com.bachelor.toolbox.target.TargetPolicyService;
import java.net.InetSocketAddress;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.util.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class TcpPortTool implements SecurityTool {
  /**
   * Ports probed in {@code quick} mode. They cover the overwhelming majority of reachable
   * services on a host, so a handful of connects both proves liveness and seeds the open-port
   * list for later stages. Everything here is still intersected with the target's allow-list.
   */
  private static final List<Integer> QUICK_PORTS =
      List.of(80, 443, 22, 21, 3389, 3306, 8080, 8443, 25, 110, 143, 53, 445, 139, 5432, 6379, 27017);

  private final TargetPolicyService policyService;
  private final PortRangeParser portRangeParser;
  private final int timeoutMillis;
  private final int maxPorts;

  public TcpPortTool(
      TargetPolicyService policyService,
      PortRangeParser portRangeParser,
      @Value("${toolbox.execution.connect-timeout-seconds:3}") int timeoutSeconds,
      @Value("${toolbox.execution.max-ports-per-task:65535}") int maxPorts) {
    this.policyService = policyService;
    this.portRangeParser = portRangeParser;
    this.timeoutMillis = Math.max(1, timeoutSeconds) * 1000;
    this.maxPorts = maxPorts;
  }

  @Override
  public String code() {
    return "tcp_ports";
  }

  @Override
  public String displayName() {
    return "TCP 端口探测";
  }

  @Override
  public String description() {
    return "仅对授权目标和允许端口执行受控 TCP 连接探测";
  }

  @Override
  public ToolExecutionResult execute(AuthorizedTarget target, Map<String, Object> parameters) {
    return execute(target, parameters, ToolExecutionObserver.NOOP);
  }

  @Override
  public ToolExecutionResult execute(
      AuthorizedTarget target, Map<String, Object> parameters, ToolExecutionObserver observer) {
    String host = policyService.validatedHost(target);
    Set<Integer> allowed = portRangeParser.parse(target.getAllowedPorts());
    String mode = Objects.toString(parameters.getOrDefault("mode", ""), "").trim();
    Set<Integer> requested;
    String requestedText;
    if ("quick".equals(mode)) {
      // Liveness + fast discovery: only the common ports that are also authorized.
      requested = new java.util.LinkedHashSet<>();
      for (Integer port : QUICK_PORTS) {
        if (allowed.contains(port)) requested.add(port);
      }
      if (requested.isEmpty()) {
        // Nothing common is authorized (e.g. an odd-only range): fall back to the first few
        // allowed ports so quick mode still has something to try.
        int guard = 0;
        for (Integer port : allowed) {
          requested.add(port);
          if (++guard >= 8) break;
        }
      }
      requestedText = requested.stream().map(String::valueOf)
          .collect(java.util.stream.Collectors.joining(","));
    } else {
      requestedText =
          Objects.toString(parameters.getOrDefault("ports", target.getAllowedPorts()), "");
      requested = portRangeParser.parse(requestedText, maxPorts);
    }
    if (!allowed.containsAll(requested)) {
      throw new ApiException("请求端口超出授权目标的允许端口范围");
    }
    observer.operation(
        "TCP_CONNECT host="
            + host
            + " ports="
            + requestedText
            + " timeout="
            + timeoutMillis
            + "ms"
            + (mode.isBlank() ? "" : " mode=" + mode));

    List<Integer> openPorts = new ArrayList<>();
    Map<Integer, String> states = new LinkedHashMap<>();
    int completed = 0;
    observer.progress(0, requested.size(), "准备探测 " + requested.size() + " 个授权端口");
    for (Integer port : requested) {
      if (observer.isCancellationRequested()) throw new ApiException("任务已取消");
      String state = probePort(host, port, observer);
      states.put(port, state);
      if ("OPEN".equals(state)) openPorts.add(port);
      completed++;
      observer.progress(
          completed,
          requested.size(),
          "TCP 端口探测 " + completed + "/" + requested.size() + "（当前端口 " + port + "）");
    }

    return new ToolExecutionResult(
        "已完成 " + requested.size() + " 个授权端口探测，发现 " + openPorts.size() + " 个开放端口（资产暴露面信息，不自动判定为漏洞）",
        Map.of(
            "host",
            host,
            "states",
            states,
            "openPorts",
            openPorts,
            "assessmentType",
            "ASSET_OBSERVATION",
            "vulnerability",
            false,
            "note",
            "开放端口仅代表可达服务；需结合未授权访问、弱口令、危险配置或已知漏洞证据后才能形成漏洞"),
        List.of());
  }

  private String probePort(String host, int port, ToolExecutionObserver observer) {
    // Non-blocking connect so cancellation lands within ~200ms even on a filtered port that a
    // blocking Socket.connect() would stall on for the full timeout. That un-interruptible
    // blocking connect was why 取消 had no visible effect until the whole scan finished.
    try (SocketChannel channel = SocketChannel.open();
        Selector selector = Selector.open()) {
      channel.configureBlocking(false);
      channel.connect(new InetSocketAddress(host, port));
      channel.register(selector, SelectionKey.OP_CONNECT);
      long deadline = System.nanoTime() + (long) timeoutMillis * 1_000_000L;
      while (System.nanoTime() < deadline) {
        if (observer.isCancellationRequested()) throw new ApiException("任务已取消");
        selector.select(200);
        if (channel.finishConnect()) return "OPEN";
      }
      return "CLOSED_OR_FILTERED";
    } catch (ApiException ex) {
      throw ex;
    } catch (Exception ex) {
      return "CLOSED_OR_FILTERED";
    }
  }
}
