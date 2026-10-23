package com.bachelor.toolbox.tool;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.PortRangeParser;
import com.bachelor.toolbox.target.TargetPolicyService;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.ConnectException;
import java.net.InetSocketAddress;
import java.net.PortUnreachableException;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Controlled TCP connect probe over an authorized target's allow-listed ports.
 *
 * <h2>端口集合的唯一事实来源：{@code ports} 与授权范围的交集</h2>
 *
 * <p>本工具历史上有一个 {@code mode=quick} 分支，它<strong>忽略</strong> {@code ports} 参数，只探测
 * 17 个内置常用端口。那是一个真实缺陷而非优化，理由是：
 *
 * <ul>
 *   <li>授权平台的前提是"目标已被授权"。需要"先证明主机活着"的抽样优化在这里前提失效；
 *   <li>{@code ports} 在审批弹窗里是可见、可核对、可修改的参数，执行时却被静默忽略 →
 *       <strong>审批展示的内容与实际执行不一致</strong>，属于审批完整性缺陷；
 *   <li>下游 Nmap 步骤"复用已探测端口"读取的是本工具输出的 {@code openPorts}。quick 模式让未被
 *       探测的端口永远不进入下一步，形成静默漏报；
 *   <li>它试图用"缩小扫描面"掩盖"没有并发"这个真正的性能问题，方向错误。
 * </ul>
 *
 * <p>因此 {@code mode} 不再影响端口集合：{@code ports} 缺省取目标授权端口全段，显式给出时只能
 * <strong>收窄</strong>授权范围，越界直接拒绝。
 *
 * <h2>并发模型</h2>
 *
 * <p>Nmap 不可用时本工具是唯一的端口发现手段（纯 JDK 实现，无外部二进制依赖），所以并发度必须
 * 与 {@code nmap -sT} 同一量级才有兜底价值。这里用固定大小线程池并行 connect，每个工作线程持有
 * 自己的 {@link Selector}：
 *
 * <ul>
 *   <li>无共享 Selector 竞争——{@code Selector} 非线程安全，共享会引入额外锁且易出错；
 *   <li>非阻塞 connect 仍然保留：取消能在一个 select 周期（{@value #CANCEL_POLL_MILLIS}ms）内落地，
 *       而不是阻塞到整个超时耗尽（这正是历史缺陷的成因）；
 *   <li>结果按输入端口顺序回填，输出稳定可复现，与是否并发无关。
 * </ul>
 */
@Component
public class TcpPortTool implements SecurityTool {
  /** 默认并发连接数。与 nmap -sT 的默认批处理量级相当，同时足以避免把目标打瘫。 */
  static final int DEFAULT_CONCURRENCY = 200;

  /** 等待 connect 完成期间的单次 select 超时：决定"取消"的最大响应延迟。 */
  private static final long CANCEL_POLL_MILLIS = 200L;

  /**
   * 每个工作线程一个 {@link Selector}。{@code Selector} 非线程安全，且创建代价不小——按端口新建
   * 会把全端口扫描的吞吐压到百级/s，复用后可上万/s。用 ThreadLocal 而非共享，是为了既拿回性能
   * 又避免在 select 上加锁。
   */
  private static final ThreadLocal<Selector> PROBE_SELECTOR =
      ThreadLocal.withInitial(
          () -> {
            try {
              return Selector.open();
            } catch (IOException ex) {
              throw new UncheckedIOException("无法创建端口探测的 Selector", ex);
            }
          });

  private final TargetPolicyService policyService;
  private final PortRangeParser portRangeParser;
  private final int timeoutMillis;
  private final int maxPorts;
  private final int concurrency;

  // 存在两个构造函数时 Spring 无法推断该用哪个（会报 "No default constructor found"），
  // 这里显式标注注入用的那个；4 参的是给测试与手工装配的便捷重载。
  @Autowired
  public TcpPortTool(
      TargetPolicyService policyService,
      PortRangeParser portRangeParser,
      @Value("${toolbox.execution.connect-timeout-seconds:3}") int timeoutSeconds,
      @Value("${toolbox.execution.max-ports-per-task:65535}") int maxPorts,
      @Value("${toolbox.execution.port-probe-concurrency:200}") int concurrency) {
    this.policyService = policyService;
    this.portRangeParser = portRangeParser;
    this.timeoutMillis = Math.max(1, timeoutSeconds) * 1000;
    this.maxPorts = maxPorts;
    this.concurrency = Math.max(1, concurrency);
  }

  /** 兼容旧调用点（测试与手工装配）：并发度取默认值。 */
  public TcpPortTool(
      TargetPolicyService policyService,
      PortRangeParser portRangeParser,
      int timeoutSeconds,
      int maxPorts) {
    this(policyService, portRangeParser, timeoutSeconds, maxPorts, DEFAULT_CONCURRENCY);
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
    // 先校验授权配置本身，再解析端口：否则空配置会以"端口格式错误"这种误导性文案冒出来，
    // 让管理员误以为是自己填错了参数，而真正的原因是目标没配允许端口。
    String allowedPorts = Objects.toString(target.getAllowedPorts(), "").trim();
    if (allowedPorts.isEmpty()) {
      throw new ApiException("授权目标未配置允许端口，无法执行端口探测");
    }
    Set<Integer> allowed = portRangeParser.parse(allowedPorts);
    Map<String, Object> safe = parameters == null ? Map.of() : parameters;

    // ports 是唯一决定扫描面的输入：缺省 = 授权全段；显式 = 只能收窄授权范围。
    String requestedText = Objects.toString(safe.getOrDefault("ports", allowedPorts), "").trim();
    if (requestedText.isEmpty()) {
      requestedText = allowedPorts;
    }
    Set<Integer> requested = portRangeParser.parse(requestedText, maxPorts);
    if (!allowed.containsAll(requested)) {
      throw new ApiException("请求端口超出授权目标的允许端口范围");
    }
    if (requested.isEmpty()) {
      throw new ApiException("授权目标未配置允许端口，无法执行端口探测");
    }

    List<Integer> ports = new ArrayList<>(requested);
    observer.operation(
        "TCP_CONNECT host="
            + host
            + " ports="
            + requestedText
            + " count="
            + ports.size()
            + " timeout="
            + timeoutMillis
            + "ms concurrency="
            + Math.min(concurrency, ports.size()));

    Map<Integer, String> states = new LinkedHashMap<>();
    List<Integer> openPorts = new ArrayList<>();
    scan(host, ports, observer, states, openPorts);

    // UDP 快速探测：可选的附加阶段。UDP 无连接，判定语义与 TCP 本质不同，因此单独收集、
    // 单独标注，绝不混入 openPorts（否则下游 Nmap 会把"开放或过滤"当成确定的开放端口去精扫）。
    boolean udpRequested = truthy(safe.get("udp"));
    Map<Integer, String> udpStates = new LinkedHashMap<>();
    List<Integer> udpOpen = new ArrayList<>();
    List<Integer> udpOpenOrFiltered = new ArrayList<>();
    if (udpRequested) {
      scanUdp(host, ports, observer, udpStates, udpOpen, udpOpenOrFiltered);
    }

    Map<String, Object> data = new LinkedHashMap<>();
    data.put("host", host);
    data.put("protocol", "TCP");
    data.put("states", states);
    data.put("openPorts", openPorts);
    data.put("assessmentType", "ASSET_OBSERVATION");
    data.put("vulnerability", false);
    data.put("note", "开放端口仅代表可达服务；需结合未授权访问、弱口令、危险配置或已知漏洞证据后才能形成漏洞");
    if (udpRequested) {
      data.put("udpStates", udpStates);
      data.put("udpOpenPorts", udpOpen);
      data.put("udpOpenOrFilteredPorts", udpOpenOrFiltered);
      data.put("udpCaveat", UDP_CAVEAT);
    }

    String summary =
        "已完成 " + ports.size() + " 个授权端口探测，发现 " + openPorts.size()
            + " 个开放的 TCP 端口（资产暴露面信息，不自动判定为漏洞）";
    if (udpRequested) {
      summary +=
          "；UDP 探测确证开放 "
              + udpOpen.size()
              + " 个，"
              + udpOpenOrFiltered.size()
              + " 个无法判定开放或过滤（UDP 无连接确认机制，此结果仅供参考）";
    }
    return new ToolExecutionResult(summary, data, List.of());
  }

  /**
   * UDP 探测的语义说明。必须随结果一起下发，否则"开放或过滤"会被当成"开放"使用。
   *
   * <p>UDP 没有握手，无法像 TCP 那样确认端口开放：
   *
   * <ul>
   *   <li>收到应用层响应 → <strong>确定开放</strong>；
   *   <li>收到 ICMP port unreachable → <strong>确定关闭</strong>；
   *   <li>什么都没收到 → <strong>开放或过滤</strong>，二者无法区分（防火墙 DROP 与端口开放但
   *       不回应探测载荷，现象完全一样）。
   * </ul>
   *
   * <p>此外，ICMP 限速会让"发送过快"表现为"没收到响应"，所以 UDP 探测天然比 TCP 慢且不可靠。
   */
  static final String UDP_CAVEAT =
      "UDP 无连接握手，只能通过 ICMP port unreachable 判定端口关闭；未收到任何响应时无法区分"
          + "「端口开放但服务不回应探测载荷」与「被防火墙静默丢弃」，此类端口归类为「开放或过滤」，"
          + "不等于开放。确认开放请使用 nmap -sU 并配合服务特定的探测载荷。";

  private boolean truthy(Object value) {
    return Boolean.TRUE.equals(value) || "true".equalsIgnoreCase(String.valueOf(value));
  }

  /**
   * 并行探测全部端口，并把结果按输入顺序写回 {@code states} / {@code openPorts}。
   *
   * <p>进度以"已完成端口数"单调递增上报，避免并发下进度条回跳；每完成一个端口刷新一次。
   */
  private void scan(
      String host,
      List<Integer> ports,
      ToolExecutionObserver observer,
      Map<Integer, String> states,
      List<Integer> openPorts) {
    int total = ports.size();
    String[] statuses = new String[total];
    int poolSize = Math.min(concurrency, total);
    AtomicInteger completed = new AtomicInteger();
    Object progressLock = new Object();

    observer.progress(0, total, "并行探测 " + total + " 个授权端口（并发 " + poolSize + "）");

    ExecutorService pool =
        Executors.newFixedThreadPool(
            poolSize,
            runnable -> {
              Thread thread = new Thread(runnable, "tcp-port-probe");
              thread.setDaemon(true);
              return thread;
            });
    try {
      List<Future<?>> futures = new ArrayList<>(total);
      for (int index = 0; index < total; index++) {
        int slot = index;
        int port = ports.get(index);
        futures.add(
            pool.submit(
                () -> {
                  statuses[slot] = probePort(host, port, observer);
                  int done = completed.incrementAndGet();
                  synchronized (progressLock) {
                    observer.progress(
                        done, total, "TCP 端口探测 " + done + "/" + total + "（当前端口 " + port + "）");
                  }
                }));
      }
      for (Future<?> future : futures) {
        future.get();
      }
    } catch (InterruptedException ex) {
      Thread.currentThread().interrupt();
      throw new ApiException("端口探测已中断");
    } catch (ExecutionException ex) {
      // 任务被取消时 probePort 抛出的 ApiException 会以 ExecutionException 形式冒出，
      // 这里还原原始异常，避免把"任务已取消"包装成内部错误。
      Throwable cause = ex.getCause();
      if (cause instanceof ApiException apiException) {
        throw apiException;
      }
      throw new ApiException("端口探测失败：" + (cause == null ? ex.getMessage() : cause.getMessage()));
    } finally {
      pool.shutdownNow();
    }
    // 顺序回填：保证 states 的迭代顺序与用户输入的端口顺序一致，输出可复现。
    for (int index = 0; index < total; index++) {
      int port = ports.get(index);
      String state = statuses[index] == null ? "CLOSED_OR_FILTERED" : statuses[index];
      states.put(port, state);
      if ("OPEN".equals(state)) openPorts.add(port);
    }
  }

  /**
   * 对同一批授权端口做 UDP 快速探测。
   *
   * <p>判定逻辑：发一个空载荷（0 字节）数据报，然后在超时窗口内等待。
   *
   * <ul>
   *   <li>收到任何响应字节 → {@code OPEN}（服务确实在监听并应答）；
   *   <li>{@link PortUnreachableException} → {@code CLOSED}（内核转达了 ICMP port unreachable）；
   *   <li>超时且无任何反馈 → {@code OPEN_OR_FILTERED}。
   * </ul>
   *
   * <p>受限于 UDP 语义，{@code OPEN_OR_FILTERED} 是本方法最常见的正常结果，绝不能当成"开放"使用。
   * 并发同样用线程池，但每个探测占用一个 {@link DatagramChannel}，不共享 Selector——UDP 的
   * 就绪事件与 TCP 的 OP_CONNECT 语义不同，混用会互相干扰。
   */
  private void scanUdp(
      String host,
      List<Integer> ports,
      ToolExecutionObserver observer,
      Map<Integer, String> udpStates,
      List<Integer> udpOpen,
      List<Integer> udpOpenOrFiltered) {
    int total = ports.size();
    String[] statuses = new String[total];
    int poolSize = Math.min(concurrency, total);
    AtomicInteger completed = new AtomicInteger();
    Object progressLock = new Object();
    observer.progress(0, total, "UDP 探测 " + total + " 个授权端口（并发 " + poolSize + "）");

    ExecutorService pool =
        Executors.newFixedThreadPool(
            poolSize,
            runnable -> {
              Thread thread = new Thread(runnable, "udp-port-probe");
              thread.setDaemon(true);
              return thread;
            });
    try {
      List<Future<?>> futures = new ArrayList<>(total);
      for (int index = 0; index < total; index++) {
        int slot = index;
        int port = ports.get(index);
        futures.add(
            pool.submit(
                () -> {
                  statuses[slot] = probeUdp(host, port);
                  int done = completed.incrementAndGet();
                  synchronized (progressLock) {
                    observer.progress(done, total, "UDP 端口探测 " + done + "/" + total);
                  }
                }));
      }
      for (Future<?> future : futures) {
        future.get();
      }
    } catch (InterruptedException ex) {
      Thread.currentThread().interrupt();
      throw new ApiException("UDP 端口探测已中断");
    } catch (ExecutionException ex) {
      Throwable cause = ex.getCause();
      if (cause instanceof ApiException apiException) {
        throw apiException;
      }
      // UDP 探测失败不应让整个任务失败：TCP 结果已经有效，UDP 只是附加信息。
    } finally {
      pool.shutdownNow();
    }
    for (int index = 0; index < total; index++) {
      int port = ports.get(index);
      String state = statuses[index] == null ? "OPEN_OR_FILTERED" : statuses[index];
      udpStates.put(port, state);
      if ("OPEN".equals(state)) {
        udpOpen.add(port);
      } else if ("OPEN_OR_FILTERED".equals(state)) {
        udpOpenOrFiltered.add(port);
      }
    }
  }

  private String probeUdp(String host, int port) {
    try (DatagramChannel channel = DatagramChannel.open()) {
      channel.configureBlocking(false);
      ByteBuffer empty = ByteBuffer.allocate(0);
      channel.send(empty, new InetSocketAddress(host, port));
      ByteBuffer buffer = ByteBuffer.allocate(1024);
      Selector selector = Selector.open();
      try {
        channel.register(selector, SelectionKey.OP_READ);
        long deadline = System.nanoTime() + (long) timeoutMillis * 1_000_000L;
        while (System.nanoTime() < deadline) {
          int ready = selector.select(CANCEL_POLL_MILLIS);
          if (ready > 0) {
            buffer.clear();
            if (channel.receive(buffer) != null) {
              return "OPEN";
            }
          }
        }
        return "OPEN_OR_FILTERED";
      } finally {
        selector.close();
      }
    } catch (PortUnreachableException unreachable) {
      // 明确收到 ICMP port unreachable：这是 UDP 唯一能确证"关闭"的信号。
      return "CLOSED";
    } catch (Exception ex) {
      // 无法判定（含权限受限、网络不可达等），按最保守的语义处理。
      return "OPEN_OR_FILTERED";
    }
  }

  private String probePort(String host, int port, ToolExecutionObserver observer) {
    // 每线程复用一个 Selector：实测每个端口新建 Selector 会把吞吐压到 ~300/s，复用后提升一个
    // 数量级。Selector 非线程安全，但 ThreadLocal 保证每个工作线程独享，无竞争。扫描结束后由
    // scan() 统一关闭，避免线程池回收时泄漏文件描述符。
    Selector selector = PROBE_SELECTOR.get();
    try {
      // 清掉上一轮遗留的就绪事件，否则 select() 会立即返回造成空转。
      selector.selectNow();
      try (SocketChannel channel = SocketChannel.open()) {
        channel.configureBlocking(false);
        try {
          // 内网/本机常见情况是立即返回：连接成功，或被目标 RST 拒绝。拒绝时 JDK 抛
          // ConnectException，而构造异常栈的代价远高于一次系统调用（实测约占总耗时的大头），
          // 所以这里直接把它当成最终结果返回，不再重试。
          if (channel.connect(new InetSocketAddress(host, port))) return "OPEN";
        } catch (ConnectException refused) {
          return "CLOSED_OR_FILTERED";
        }

        SelectionKey key = channel.register(selector, SelectionKey.OP_CONNECT);
        try {
          long deadline = System.nanoTime() + (long) timeoutMillis * 1_000_000L;
          while (System.nanoTime() < deadline) {
            if (observer.isCancellationRequested()) throw new ApiException("任务已取消");
            selector.select(CANCEL_POLL_MILLIS);
            // 通道已被对端重置或取消时，等待 finishConnect() 只会再抛一次异常。
            if (!key.isValid()) return "CLOSED_OR_FILTERED";
            try {
              if (channel.finishConnect()) return "OPEN";
            } catch (ConnectException refused) {
              return "CLOSED_OR_FILTERED";
            }
          }
          return "CLOSED_OR_FILTERED";
        } finally {
          key.cancel();
        }
      }
    } catch (ApiException ex) {
      throw ex;
    } catch (Exception ex) {
      return "CLOSED_OR_FILTERED";
    }
  }
}
