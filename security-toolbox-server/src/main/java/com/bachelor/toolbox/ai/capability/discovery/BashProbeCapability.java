package com.bachelor.toolbox.ai.capability.discovery;

import com.bachelor.toolbox.ai.capability.CapabilityKind;
import com.bachelor.toolbox.ai.capability.RiskLevel;
import com.bachelor.toolbox.ai.capability.core.AbstractCoreCapability;
import com.bachelor.toolbox.ai.capability.core.AiCapabilityLayer;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * {@code bash_probe} —— 通用命令行探测能力（设计文档 §7）。
 *
 * <p>按 §7 的定位，Bash <strong>是并列的补充能力</strong>，与平台能力平等，而非替代品：主力是平台能力（工作流、流量分析、
 * 报告生成），Bash 用于补充平台未覆盖的外部工具链、临时组合探测、快速验证。同等治理——它与平台能力走<strong>同一个</strong>
 * {@code CapabilityGate}，不因是 shell 就降低标准。
 *
 * <h2>元数据（§7 指定）</h2>
 *
 * <pre>
 * code = "bash_probe", kind = EXECUTE, risk = SENSITIVE, requiresApproval = true
 * </pre>
 *
 * <p>补充说明：{@link RiskLevel#SENSITIVE} 而非 {@code DESTRUCTIVE}，与 §7 一致。但护栏 L-B 对 {@code bash_probe}
 * 有<strong>额外</strong>要求（{@code CapabilityGate#requiresExplicitEnable} 显式列了 {@code bash_probe}）：
 * 它必须在 {@code toolbox.agent.guard.whitelist} 中显式开启才可由 Agent 调用，即<strong>默认关闭</strong>。
 * 这与"风险等级是 SENSITIVE"并不矛盾——前者是"能力本身多危险"，后者是"要不要默认开"。Bash 的默认关闭是刻意的：
 * 它是唯一能绕过 L-A 授权边界的通道（见下）。
 *
 * <h2>目标绑定：{@link BindingMode#UNRESOLVED} —— 恒返回哨兵</h2>
 *
 * <p>命令字符串里可以出现任意主机名、IP、URL（{@code nmap 10.0.0.1}、{@code curl http://x}、{@code dig y}），
 * <strong>无法静态解析出本次调用触及哪个授权目标</strong>。按 §4.1 三态语义：
 *
 * <ul>
 *   <li>返回空集 = 宣称"本能力不触及任何目标" → 护栏跳过 L-A → <strong>fail-open</strong>，这是明确禁止的；
 *   <li>因此返回哨兵 {@link #TARGET_BINDING_UNRESOLVED} → 护栏 <strong>fail-closed 拒绝</strong>，由人工确认兜底。
 * </ul>
 *
 * <p>拒绝是正确结论：{@code bash_probe} 的可达面本质上无法被授权边界约束（见"固有局限"），所以"护栏拦不住它"这件事
 * 必须表现为"护栏拒绝它"，而不是"护栏放行它"。
 *
 * <h2>⚠️ 固有局限（如实记录，不得掩盖）</h2>
 *
 * <p>详细的四条局限见 {@link BashProbePolicy} 的类注释。最核心的一条在此重申：
 *
 * <p><strong>外部工具的网络出口不受应用层控制（§10 局限 7）。</strong>本能力约束的是"进程怎么起"，不是"进程能连哪里"。
 * 一旦命令被允许执行，它的出站连接<strong>不经过</strong> {@code TargetPolicyService}——也就是说 {@code bash_probe} 是
 * 唯一一条<strong>绕过 L-A 授权边界</strong>的通道。平台能力路径不受此影响，因为它们的网络动作都在平台代码里。
 *
 * <p>因此本能力提供的保证应当被精确表述为：
 *
 * <blockquote>
 * {@code bash_probe} 通过"默认关闭 + 逐次人工确认 + 进程级约束（工作目录/超时/环境白名单/非提权/复杂度上限）"
 * 降低误用风险，<strong>但不对授权边界提供保证</strong>；其网络出口属已知残余风险，需在论文中如实说明。
 * </blockquote>
 *
 * <p>另外两条必须承认的：
 *
 * <ul>
 *   <li><strong>黑名单不等于安全证明</strong>：shell、PowerShell、以及 {@code python3 -c}、{@code nmap --script}
 *       等图灵完备的"参数"无法用字符串规则判定。真正的控制点是人工确认，黑名单只降低"顺手写出危险命令"的概率。
 *   <li><strong>超时只杀直接子进程</strong>：工具自行 fork 的守护进程可能存活。
 * </ul>
 *
 * <h2>为什么仍要实现它（而不是删掉）</h2>
 *
 * <p>§7 的立场是：平台能力不可能覆盖全部场景（用户装了 nmap、nuclei、openssl、dig，各有各的组合用法）。
 * 若平台不提供 Bash，Agent 就会去用 {@code invoke_endpoint} 找一个能执行命令的端点——那才是真正的失控。
 * <strong>把通道放在明处、加确认、留审计</strong>，比让 Agent 绕路去找更危险的口子要好。这与 §6.9
 * "让 Agent 能做到，但在执行前拒绝"的整体立场一致。
 */
@Component
public class BashProbeCapability extends AbstractCoreCapability {

  /** 能力码（§7 指定）。 */
  public static final String CODE = "bash_probe";

  /** 动作分级取值：平台按此判断是否属 INTRUSIVE（护栏 {@code ApprovalPolicy} 也读这个键）。 */
  public static final List<String> ACTION_CLASSES = List.of("SAFE", "READ_ONLY", "RECON", "INTRUSIVE");

  private final Path workspaceRoot;

  public BashProbeCapability(
      @Value("${toolbox.agent.bash.workspace:./data/agent-workspace}") String workspace) {
    super(
        CODE,
        "命令行探测",
        "执行一条受约束的命令行指令，用于平台能力未覆盖的外部工具场景（如 nmap、curl、dig、openssl、python3）。"
            + "参数：command（要执行的命令，单行、长度 ≤ "
            + BashProbePolicy.MAX_COMMAND_LENGTH
            + " 字符）、cwd（可选工作目录，必须位于 Agent 工作区内）、timeoutSeconds（可选超时，默认 "
            + BashProbePolicy.DEFAULT_TIMEOUT_SECONDS
            + " 秒、上限 "
            + BashProbePolicy.MAX_TIMEOUT_SECONDS
            + " 秒）、actionClass（SAFE / READ_ONLY / RECON / INTRUSIVE）。"
            + "约束：工作目录限定在工作区内、超时强杀、只注入白名单环境变量、拒绝提权前缀与破坏性命令、限制命令复杂度。"
            + "⚠️ 固有局限：外部工具的网络出口不受平台授权边界约束，因此本能力是唯一可能绕过授权校验的通道，"
            + "默认关闭且需逐次人工确认。优先使用平台能力（create_task、run_workflow、query_traffic 等），"
            + "仅在平台未覆盖时使用本能力。",
        CapabilityKind.EXECUTE,
        RiskLevel.SENSITIVE,
        true,
        BindingMode.UNRESOLVED,
        AiCapabilityLayer.L1);
    this.workspaceRoot = Paths.get(workspace == null || workspace.isBlank() ? "./data/agent-workspace" : workspace);
  }

  @Override
  public Map<String, Object> parameterSchema() {
    Map<String, Object> properties = new LinkedHashMap<>();
    properties.put(
        "command",
        Map.of(
            "type", "string",
            "maxLength", BashProbePolicy.MAX_COMMAND_LENGTH,
            "description",
            "要执行的单行命令；不得包含换行、提权前缀或破坏性操作，段数上限 "
                + BashProbePolicy.MAX_SEGMENTS));
    properties.put(
        "cwd",
        property("string", "可选：工作目录，相对路径基于 Agent 工作区；不得逃逸出工作区"));
    properties.put(
        "timeoutSeconds",
        integerProperty(1, "可选：超时秒数，默认 " + BashProbePolicy.DEFAULT_TIMEOUT_SECONDS
            + "，上限 " + BashProbePolicy.MAX_TIMEOUT_SECONDS));
    properties.put(
        "actionClass",
        enumProperty(
            ACTION_CLASSES,
            "动作分级；INTRUSIVE 会触发逐次人工确认（护栏 ApprovalPolicy 读取该字段）"));
    return objectSchema(properties, List.of("command"));
  }

  @Override
  protected void validateCoreParams(Map<String, Object> params) {
    String command = requireText(params, "command");
    // 五条轻量约束：命令长度/复杂度/提权/破坏性模式、工作目录、超时区间，全部在参数校验阶段完成。
    BashProbePolicy.validateCommand(command);
    BashProbePolicy.resolveWorkingDirectory(workspaceRoot, optionalText(params, "cwd"));
    // 严格解析：timeoutSeconds 的取值本身参与安全约束（防挂起），
    // 因此传 0 / 负数 / 非数字必须**拒绝**，绝不能折叠成默认 30 秒（那会让调用方以为"立即超时"而实际得到 30 秒窗口）。
    BashProbePolicy.boundedTimeout(optionalStrictPositiveInt(params, "timeoutSeconds"));
  }

  /** 工作区根目录（供审计与测试断言）。 */
  public Path workspaceRoot() {
    return workspaceRoot;
  }

  /**
   * 执行命令。
   *
   * <p>调用前必须已经过 {@link #validateParams}（护栏 L-C 会调用它）。本方法<strong>再校验一遍</strong>，
   * 因为"能力可被直接调用"这一点不能假设——§10 失败模式"校验只覆盖部分调用路径（X-7）"说的就是这种假设。
   *
   * @param command 命令
   * @param cwd 工作目录（可为 {@code null}）
   * @param timeoutSeconds 超时（可为 {@code null}）
   * @param actionClass 动作分级（可为 {@code null}）
   * @return 执行结果：退出码、stdout、stderr、耗时、是否超时、实际使用的工作目录与环境变量名
   */
  public Map<String, Object> execute(
      String command, String cwd, Integer timeoutSeconds, String actionClass) {
    BashProbePolicy.validateCommand(command);
    Path workingDirectory = BashProbePolicy.resolveWorkingDirectory(workspaceRoot, cwd);
    int timeout = BashProbePolicy.boundedTimeout(timeoutSeconds);

    ProcessBuilder builder = new ProcessBuilder(shellCommand(command));
    builder.directory(workingDirectory.toFile());
    // 约束三：不继承父进程环境，只注入白名单键。这是防"Agent 用 env 把 API Key 带走"的关键一步。
    Map<String, String> environment = builder.environment();
    environment.clear();
    environment.putAll(BashProbePolicy.sanitizedEnvironment(System.getenv()));

    long startedAt = System.nanoTime();
    Map<String, Object> result = new LinkedHashMap<>();
    result.put("command", command);
    result.put("actionClass", actionClass == null ? "INTRUSIVE" : actionClass.toUpperCase(Locale.ROOT));
    result.put("cwd", workingDirectory.toString());
    result.put("timeoutSeconds", timeout);
    result.put("environmentKeys", new ArrayList<>(environment.keySet()));

    Process process = null;
    try {
      process = builder.start();
      // ⚠️ 必须在等待超时之前就把 stdout/stderr 排空，且必须并发排空。
      //
      // 这里有一个实测踩到的陷阱（本任务的单元测试暴露）：如果先同步 readBounded(stdout) 再 awaitOrKill，
      // 那么"读流"这一步会阻塞到子进程关闭管道为止 —— 于是一个挂起的命令会让读流永久阻塞，
      // 超时根本轮不到生效，process.waitFor(timeout) 形同虚设。实测 sleep 30 的命令在 2 秒超时下
      // 仍耗时 29.6 秒返回，证明"防挂起"这一约束当时是失效的。
      //
      // 正确做法：把两个流各自交给一个后台线程排空，主线程只负责 waitFor(timeout)。
      // 这样超时由主线程独立掌握，不受流是否关闭的影响。
      StreamDrain stdoutDrain = StreamDrain.start(process.getInputStream());
      StreamDrain stderrDrain = StreamDrain.start(process.getErrorStream());
      boolean finished = BashProbePolicy.awaitOrKill(process, timeout);
      long elapsedMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startedAt);
      byte[] stdout = stdoutDrain.awaitAndGet();
      byte[] stderr = stderrDrain.awaitAndGet();
      result.put("finished", finished);
      result.put("timedOut", !finished);
      result.put("exitCode", finished ? process.exitValue() : -1);
      result.put("stdout", BashProbePolicy.truncateOutput(stdout));
      result.put("stderr", BashProbePolicy.truncateOutput(stderr));
      result.put("durationMs", elapsedMs);
      if (!finished) {
        result.put(
            "note",
            "命令超时（" + timeout + " 秒）已被强制终止；注意超时只杀直接子进程，工具自行 fork 的子进程可能存活");
      }
      return Map.copyOf(result);
    } catch (IOException error) {
      long elapsedMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startedAt);
      result.put("finished", false);
      result.put("timedOut", false);
      result.put("exitCode", -1);
      result.put("stdout", "");
      result.put("stderr", "命令启动失败: " + error.getMessage());
      result.put("durationMs", elapsedMs);
      return Map.copyOf(result);
    } finally {
      if (process != null && process.isAlive()) {
        process.destroyForcibly();
      }
    }
  }

  /** 构造 shell 调用：POSIX 用 {@code sh -c}，Windows 用 {@code cmd /c}。 */
  private static List<String> shellCommand(String command) {
    boolean windows = System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("win");
    if (windows) {
      return List.of("cmd.exe", "/c", command);
    }
    return List.of("/bin/sh", "-c", command);
  }

  /**
   * 有界读取子进程输出。
   *
   * <p>刻意在读满上限后<strong>继续排空</strong>而不是关闭流：直接关闭会让子进程收到 SIGPIPE 提前死亡，掩盖真实行为。
   * 这里读到上限后丢弃剩余内容，保证子进程能正常跑完。
   *
   * <p>本方法会阻塞到流关闭，因此<strong>绝不能在主线程上、在超时等待之前调用</strong>——见 {@link StreamDrain}。
   */
  private static byte[] readBounded(InputStream stream) throws IOException {
    ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    byte[] chunk = new byte[8192];
    int read;
    while ((read = stream.read(chunk)) != -1) {
      if (buffer.size() < BashProbePolicy.MAX_OUTPUT_BYTES) {
        int allowed = Math.min(read, BashProbePolicy.MAX_OUTPUT_BYTES - buffer.size());
        buffer.write(chunk, 0, allowed);
      }
    }
    return buffer.toByteArray();
  }

  /**
   * 在后台线程排空一个子进程输出流。
   *
   * <p>存在意义：把"读流"与"等超时"解耦。若在主线程顺序执行"读流 → 等超时"，读流会阻塞到管道关闭，
   * 挂起的命令会让超时约束完全失效（本任务实测：2 秒超时下 sleep 30 仍耗时 29.6 秒）。
   *
   * <p>{@link #awaitAndGet()} 带兜底等待：子进程被强杀后管道通常立即关闭，但若平台未及时释放，
   * 这里最多再等 2 秒就返回已读到的内容，<strong>不允许</strong>因为读流问题让整个能力调用挂住。
   */
  private static final class StreamDrain {
    private final Thread thread;
    private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();

    private StreamDrain(InputStream stream) {
      this.thread =
          new Thread(
              () -> {
                try {
                  byte[] chunk = new byte[8192];
                  int read;
                  while ((read = stream.read(chunk)) != -1) {
                    if (buffer.size() < BashProbePolicy.MAX_OUTPUT_BYTES) {
                      int allowed = Math.min(read, BashProbePolicy.MAX_OUTPUT_BYTES - buffer.size());
                      buffer.write(chunk, 0, allowed);
                    }
                  }
                } catch (IOException ignored) {
                  // 进程被强杀时管道会以异常关闭，这是预期路径，不是错误。
                }
              },
              "bash-probe-drain");
      this.thread.setDaemon(true);
    }

    static StreamDrain start(InputStream stream) {
      StreamDrain drain = new StreamDrain(stream);
      drain.thread.start();
      return drain;
    }

    /** 等待排空线程收尾（最多 2 秒），返回已读到的字节。 */
    byte[] awaitAndGet() {
      try {
        thread.join(2000);
      } catch (InterruptedException interrupted) {
        Thread.currentThread().interrupt();
      }
      return buffer.toByteArray();
    }
  }

  /** 供文档与测试：环境变量白名单（只读）。 */
  public static List<String> environmentWhitelist() {
    return BashProbePolicy.ENV_WHITELIST;
  }

  /** 供文档与测试：被拒绝的破坏性命令模式名（只读）。 */
  public static java.util.Set<String> deniedCommandPatterns() {
    return BashProbePolicy.deniedPatternNames();
  }

  /** 供测试：暴露策略常量。 */
  public static Map<String, Object> policySnapshot() {
    Map<String, Object> snapshot = new LinkedHashMap<>();
    snapshot.put("maxCommandLength", BashProbePolicy.MAX_COMMAND_LENGTH);
    snapshot.put("maxSegments", BashProbePolicy.MAX_SEGMENTS);
    snapshot.put("defaultTimeoutSeconds", BashProbePolicy.DEFAULT_TIMEOUT_SECONDS);
    snapshot.put("maxTimeoutSeconds", BashProbePolicy.MAX_TIMEOUT_SECONDS);
    snapshot.put("maxOutputBytes", BashProbePolicy.MAX_OUTPUT_BYTES);
    snapshot.put("environmentWhitelist", BashProbePolicy.ENV_WHITELIST);
    snapshot.put("deniedPatterns", new ArrayList<>(BashProbePolicy.deniedPatternNames()));
    snapshot.put("usesShell", System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("win") ? "cmd.exe /c" : "/bin/sh -c");
    return Map.copyOf(snapshot);
  }
}
