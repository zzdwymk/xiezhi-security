package com.bachelor.toolbox.dependency;

import com.bachelor.toolbox.dependency.CommandRunner.CommandResult;
import com.bachelor.toolbox.dependency.SystemDependenciesResponse.DependencyStatus;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Files;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Service;

@Service
public class DependencyDetectionService {
  private static final Logger log = LoggerFactory.getLogger(DependencyDetectionService.class);

  private static final int MAX_DETECTION_WORKERS = 12;
  private static final Duration COMMAND_TIMEOUT = Duration.ofMillis(3500);
  // Metasploit 的 msfconsole 由 Windows 上的嵌入式 Ruby 驱动，冷启动很不稳定，
// 实测首次打印 Framework Version 需 12~20 秒，冷启动/杀软较慢时可超过 30 秒。
// 放宽到 45 秒尽力读出版本；即使仍超时也会按“已安装但版本未知”降级，不报失败。
  private static final Duration MSF_COMMAND_TIMEOUT = Duration.ofSeconds(45);
  private static final Duration ZAP_COMMAND_TIMEOUT = Duration.ofSeconds(25);
  // 依赖检测结果跨页面复用：漏洞知识库页、发起检测前都通过非强制刷新接口读取同一份缓存，
// 避免频繁重跑最慢的 Metasploit 冷启动探测。检测依赖页的"重新检测"走 forceRefresh，不受影响。
// 延长到 60 秒，使短时间内往返多个页面能直接复用检测依赖页已探测出的结果。
private static final Duration CACHE_TTL = Duration.ofSeconds(60);
  private static final Duration WORKER_SHUTDOWN_TIMEOUT = Duration.ofMillis(200);
  private static final String UNKNOWN_VERSION = "unknown";
  private static final Pattern ANSI_ESCAPE =
      Pattern.compile("\\x1B(?:[@-Z\\\\-_]|\\[[0-?]*[ -/]*[@-~])");

  private final ExecutableLocator locator;
  private final CommandRunner commandRunner;
  private final NmapExecutableResolver nmapExecutableResolver;
  private final Environment environment;
  private final ToolDirectoryHasher toolDirectoryHasher;
  private volatile CachedDetection cachedDetection;

  public DependencyDetectionService(
      ExecutableLocator locator,
      CommandRunner commandRunner,
      NmapExecutableResolver nmapExecutableResolver,
      Environment environment,
      ToolDirectoryHasher toolDirectoryHasher) {
    this.locator = locator;
    this.commandRunner = commandRunner;
    this.nmapExecutableResolver = nmapExecutableResolver;
    this.environment = environment;
    this.toolDirectoryHasher = toolDirectoryHasher;
  }

  public SystemDependenciesResponse detect() {
    return detect(false);
  }

  public synchronized SystemDependenciesResponse detect(boolean forceRefresh) {
    if (!forceRefresh) {
      SystemDependenciesResponse cachedResponse = findCachedResponse(System.nanoTime());
      if (cachedResponse != null) {
        return cachedResponse;
      }
    }

    List<DependencyDescriptor> descriptors = dependencyDescriptors();
    List<DependencyStatus> dependencies = detectAll(descriptors);
    SystemDependenciesResponse response =
        new SystemDependenciesResponse(
            System.getProperty("os.name", "unknown"),
            System.getProperty("os.arch", "unknown"),
            activeDatabaseName(),
            dependencies);
    cachedDetection = new CachedDetection(System.nanoTime(), response);
    return response;
  }

  public void detectStreaming(
      Consumer<List<DependencyStatus>> onManifest,
      Consumer<DependencyStatus> onEach,
      Consumer<List<DependencyStatus>> onComplete) {
    List<DependencyDescriptor> descriptors = dependencyDescriptors();
    // 先回传“清单”：列出将在检测的每项依赖（无状态/哈希），让前端逐项预置为“检测中”占位。
    onManifest.accept(manifests(descriptors));
    int workerCount = Math.min(MAX_DETECTION_WORKERS, descriptors.size());
    ExecutorService workers = Executors.newFixedThreadPool(workerCount);
    List<DependencyStatus> results = Collections.synchronizedList(new ArrayList<>());
    AtomicInteger remaining = new AtomicInteger(descriptors.size());

    for (DependencyDescriptor descriptor : descriptors) {
      workers.submit(
          () -> {
            DependencyStatus status = detectSafely(descriptor);
            results.add(status);
            try {
              onEach.accept(status);
            } catch (Exception ignored) {
              // SSE 连接可能已断开，检测继续执行并写入缓存。
            }
            if (remaining.decrementAndGet() == 0) {
              List<DependencyStatus> sorted = sortInDescriptorOrder(results, descriptors);
              SystemDependenciesResponse response =
                  new SystemDependenciesResponse(
                      System.getProperty("os.name", "unknown"),
                      System.getProperty("os.arch", "unknown"),
                      activeDatabaseName(),
                      sorted);
              cachedDetection = new CachedDetection(System.nanoTime(), response);
              try {
                onComplete.accept(sorted);
              } catch (Exception ignored) {
                // 连接已断开，忽略。
              }
              workers.shutdown();
            }
          });
    }
  }

  /** 生成“检测中”占位清单：仅含名称/类别/是否必需，无状态、无哈希。
   *  前端据此先铺全部项，待逐项结果回传后覆盖为真实状态；未回的项保持“检测中”转圈。 */
  private List<DependencyStatus> manifests(List<DependencyDescriptor> descriptors) {
    return descriptors.stream()
        .map(
            d ->
                new DependencyStatus(
                    d.name(),
                    null,
                    null,
                    null,
                    d.required(),
                    d.category(),
                    null,
                    null,
                    null))
        .toList();
  }

  private List<DependencyStatus> sortInDescriptorOrder(
      List<DependencyStatus> results, List<DependencyDescriptor> descriptors) {
    Map<String, DependencyStatus> byName =
        results.stream()
            .collect(
                Collectors.toMap(
                    DependencyStatus::name, status -> status, (first, second) -> first));
    return descriptors.stream()
        .map(descriptor -> byName.get(descriptor.name()))
        .filter(Objects::nonNull)
        .toList();
  }

  private SystemDependenciesResponse findCachedResponse(long nowNanos) {
    CachedDetection cached = cachedDetection;
    if (cached == null || nowNanos - cached.createdAtNanos() >= CACHE_TTL.toNanos()) {
      return null;
    }
    return cached.response();
  }

  private List<DependencyStatus> detectAll(List<DependencyDescriptor> descriptors) {
    int workerCount = Math.min(MAX_DETECTION_WORKERS, descriptors.size());
    ExecutorService workers = Executors.newFixedThreadPool(workerCount);
    try {
      List<Future<DependencyStatus>> futures = submitDetections(workers, descriptors);
      return collectDetectionResults(futures);
    } catch (InterruptedException ex) {
      Thread.currentThread().interrupt();
      throw new IllegalStateException("依赖检测被中断", ex);
    } catch (Exception ex) {
      throw new IllegalStateException("依赖检测失败", ex);
    } finally {
      stopWorkers(workers);
    }
  }

  private List<Future<DependencyStatus>> submitDetections(
      ExecutorService workers, List<DependencyDescriptor> descriptors) {
    List<Future<DependencyStatus>> futures = new ArrayList<>(descriptors.size());
    for (DependencyDescriptor descriptor : descriptors) {
      futures.add(workers.submit(() -> detectSafely(descriptor)));
    }
    return futures;
  }

  private List<DependencyStatus> collectDetectionResults(List<Future<DependencyStatus>> futures)
      throws Exception {
    List<DependencyStatus> dependencies = new ArrayList<>(futures.size());
    for (Future<DependencyStatus> future : futures) {
      dependencies.add(future.get());
    }
    return dependencies;
  }

  private void stopWorkers(ExecutorService workers) {
    workers.shutdownNow();
    try {
      workers.awaitTermination(WORKER_SHUTDOWN_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS);
    } catch (InterruptedException ex) {
      Thread.currentThread().interrupt();
    }
  }

  private DependencyStatus detectSafely(DependencyDescriptor descriptor) {
    try {
      return detectDependency(descriptor);
    } catch (Exception ex) {
      log.warn("依赖检测执行失败，dependency={}", descriptor.name(), ex);
      return buildStatus(descriptor, DetectionStatus.ERROR, null, null, "依赖检测执行失败。");
    }
  }

  private DependencyStatus detectDependency(DependencyDescriptor descriptor) {
    Optional<Path> located = locator.find(descriptor.candidates());
    if (located.isEmpty()) {
      return buildMissingStatus(descriptor);
    }
    return inspectLocatedDependency(descriptor, located.get());
  }

  private DependencyStatus buildMissingStatus(DependencyDescriptor descriptor) {
    String message = descriptor.required() ? "未检测到，相关功能不可用。" : "未检测到，可按需安装。";
    return buildStatus(descriptor, DetectionStatus.MISSING, null, null, message);
  }

  private DependencyStatus inspectLocatedDependency(
      DependencyDescriptor descriptor, Path executable) {
    String safePath = sanitizePath(executable);
    if (descriptor.arguments().isEmpty()) {
      return buildStatus(
          descriptor, DetectionStatus.AVAILABLE, UNKNOWN_VERSION, safePath, "已检测到安装目录或启动文件。");
    }

    CommandResult result =
        commandRunner.run(executable, descriptor.arguments(), descriptor.timeout());
    return evaluateVersionCommand(descriptor, safePath, result);
  }

  private DependencyStatus evaluateVersionCommand(
      DependencyDescriptor descriptor, String safePath, CommandResult result) {
    String output = cleanOutput(result.output());
    String version = resolveVersion(descriptor, safePath, output);
    if (result.timedOut()) {
      // 首次运行/冷启动较慢的工具（Metasploit/ZAP）超时，
      // 若可执行文件已就位，将其视为“已安装”，尽力解析版本或标明超时。
      if (descriptor.timeoutResolvesAsAvailable()) {
        String msg = UNKNOWN_VERSION.equals(version)
            ? "已安装；版本检测超时（首次运行较慢），可稍后重新检测获取版本。"
            : "可用（版本检测较慢，已根据本地元数据读取版本）。";
        return buildStatus(
            descriptor,
            DetectionStatus.AVAILABLE,
            version,
            safePath,
            msg);
      }
      return buildStatus(
          descriptor,
          DetectionStatus.TIMEOUT,
          version,
          safePath,
          String.format(Locale.ROOT, "版本检测超过 %.1f 秒，进程已终止。", descriptor.timeout().toMillis() / 1000.0));
    }
    if (result.errorMessage() != null) {
      if (descriptor.timeoutResolvesAsAvailable() && !UNKNOWN_VERSION.equals(version)) {
        return buildStatus(descriptor, DetectionStatus.AVAILABLE, version, safePath, "可用。");
      }
      return buildStatus(descriptor, DetectionStatus.ERROR, null, safePath, "已找到，但无法执行版本检测。");
    }
    if (!output.isBlank() && !descriptor.outputValidator().test(output)) {
      return buildStatus(
          descriptor,
          DetectionStatus.INCOMPATIBLE,
          version,
          safePath,
          descriptor.incompatibleMessage());
    }
    if (result.exitCode() != 0) {
      if (descriptor.timeoutResolvesAsAvailable() && !UNKNOWN_VERSION.equals(version)) {
        return buildStatus(descriptor, DetectionStatus.AVAILABLE, version, safePath, "可用。");
      }
      return buildStatus(
          descriptor,
          DetectionStatus.ERROR,
          version,
          safePath,
          "版本命令执行失败，退出码 " + result.exitCode() + "。");
    }
    return buildStatus(
        descriptor, DetectionStatus.AVAILABLE, version, safePath, "可用。");
  }

  private String resolveVersion(DependencyDescriptor descriptor, String safePath, String output) {
    String parsed = parseVersion(descriptor, output);
    if (UNKNOWN_VERSION.equals(parsed) && "OWASP ZAP".equals(descriptor.name())) {
      String fromPath = zapVersionFromPath(safePath);
      if (!UNKNOWN_VERSION.equals(fromPath)) {
        return fromPath;
      }
    }
    return parsed;
  }

  private DependencyStatus buildStatus(
      DependencyDescriptor descriptor,
      DetectionStatus status,
      String version,
      String path,
      String message) {
    String name = descriptor.name();
    String statusName = status.name();
    boolean available = status == DetectionStatus.AVAILABLE;
    // 仅“可用”的依赖才生成哈希：hash 是已被检测到且可用的指纹。未安装/错误/不兼容等状态
    // 不产生哈希，避免在依赖页看到“没装却有哈希”的误导（缺失依赖仅显示暂无哈希）。
    String capabilityHash =
        available ? DependencyStatus.hashOf(name, statusName, version) : null;
    return new DependencyStatus(
        name,
        statusName,
        version,
        path,
        descriptor.required(),
        descriptor.category(),
        message.trim(),
        capabilityHash,
        available ? toolDirHash(path) : null);
  }

  /**
   * 对位于 {@code TOOLBOX_TOOLS_DIR} 下的工具目录生成目录内容哈希（排除 {@code .toolbox-hash}）。
   * 主动检测启动时可对同一目录重算比对以确认扫描器确实存在。非 tools 目录或读取失败返回 null。
   */
  private String toolDirHash(String path) {
    if (path == null || path.isBlank()) {
      return null;
    }
    try {
      Path root = toolsRoot();
      if (root == null) {
        return null;
      }
      Path located = Path.of(path);
      Path resolved =
          Files.isDirectory(located) ? located : (located.getParent() != null ? located.getParent() : located);
      Path normalized = resolved.toAbsolutePath().normalize();
      if (!normalized.startsWith(root.toAbsolutePath().normalize())) {
        return null;
      }
      return toolDirectoryHasher.hashDirectory(normalized);
    } catch (Exception ex) {
      log.debug("生成工具目录哈希失败，path={}", path, ex);
      return null;
    }
  }

  private Path toolsRoot() {
    String value = environment.getProperty("TOOLBOX_TOOLS_DIR");
    if (value == null || value.isBlank()) {
      return null;
    }
    return Path.of(value.trim());
  }

  /**
   * 主动检测启动时的扫描器目录核对：确认工具目录仍然存在且非空，即为“扫描器确实在”。
   *
   * <p>早期版本通过「重算整个目录内容哈希并与 {@code .toolbox-hash} 比对」来判定，但工具目录通常包含
   * 数据库、日志、临时文件、版本更新等易变内容，任何文件变化都会让哈希失配，导致手动清空并重新生成
   * {@code .toolbox-hash} 才能恢复，反复误报「目录与记录不一致」。这里改为只确认目录存在（存在性即
   * 证明扫描器在位），不再被目录内容是否变化所干扰。目录不在 tools 下或无法定位时返回 true（不阻断，
   * 交由既有依赖存在性判断）；仅当目录确实缺失时才返回 false。
   */
  public boolean verifyToolDir(String path) {
    if (path == null || path.isBlank()) {
      return true;
    }
    try {
      Path root = toolsRoot();
      if (root == null) {
        return true;
      }
      Path located = Path.of(path);
      Path resolved =
          Files.isDirectory(located) ? located : (located.getParent() != null ? located.getParent() : located);
      Path normalized = resolved.toAbsolutePath().normalize();
      return Files.isDirectory(normalized);
    } catch (Exception ex) {
      log.debug("核验工具目录失败，path={}", path, ex);
      return true;
    }
  }

  public String activeDatabase() {
    return activeDatabaseName();
  }

  private String activeDatabaseName() {
    String url = environment.getProperty("spring.datasource.url", "");
    if (url.toLowerCase(Locale.ROOT).contains("jdbc:h2")) {
      return "H2";
    }
    if (url.toLowerCase(Locale.ROOT).contains("postgresql")) {
      return "PostgreSQL";
    }
    String fallback = url.isBlank() ? "unknown" : url;
    return fallback;
  }

  private List<DependencyDescriptor> dependencyDescriptors() {
    boolean windows = isWindows();
    Predicate<String> anyOutput = output -> !output.isBlank();

    return List.of(
        descriptor(
            "Java",
            javaCandidates(windows),
            List.of("-version"),
            true,
            "RUNTIME",
            anyOutput,
            "检测到的 Java 无法识别。"),
        descriptor(
            "Nmap",
            nmapExecutableResolver.candidates(),
            List.of("--version"),
            false,
            "SCANNER",
            output -> containsIgnoreCase(output, "nmap version"),
            "检测到的命令不是受支持的 Nmap。"),
        descriptor(
            "Npcap",
            npcapCandidates(),
            List.of(),
            false,
            "DRIVER",
            anyOutput,
            ""),
        descriptor(
            "OpenSSL",
            List.of("openssl"),
            List.of("version"),
            false,
            "CRYPTO",
            output -> containsIgnoreCase(output, "openssl"),
            "检测到的命令不是 OpenSSL。"),
        descriptor(
            "curl",
            curlCandidates(windows),
            List.of("--version"),
            false,
            "HTTP_CLIENT",
            output -> containsIgnoreCase(output, "curl "),
            "检测到的命令不是 curl。"),
        descriptor(
            "Python",
            List.of("python", "python3"),
            List.of("--version"),
            false,
            "RUNTIME",
            output -> containsIgnoreCase(output, "python "),
            "检测到的命令不是 Python。"),
        descriptor(
            "PostgreSQL",
            postgresqlCandidates(windows),
            List.of("--version"),
            false,
            "DATABASE",
            output -> containsIgnoreCase(output, "psql"),
            "检测到的命令不是 PostgreSQL psql。"),
        descriptor(
            "Nuclei",
            scannerCandidates("NUCLEI_PATH", "nuclei"),
            List.of("-disable-update-check", "-version"),
            false,
            "SCANNER",
            output -> containsIgnoreCase(output, "nuclei"),
            "检测到的命令不是 ProjectDiscovery Nuclei。"),
        descriptor(
            "Afrog",
            scannerCandidates("AFROG_PATH", "afrog"),
            List.of("-disable-update-check", "-version"),
            false,
            "SCANNER_ADAPTER",
            output -> containsIgnoreCase(output, "afrog"),
            "检测到的命令不是 Afrog。当前仅检测版本，不默认执行。"),
        descriptor(
            "Xray",
            scannerCandidates("XRAY_PATH", "xray", "xray_windows_amd64.exe"),
            List.of("version"),
            false,
            "SCANNER_ADAPTER",
            output -> containsIgnoreCase(output, "xray"),
            "检测到的命令不是 Xray。当前仅检测版本，不默认执行。"),
        descriptor(
            "fscan",
            scannerCandidates("FSCAN_PATH", "fscan"),
            // fscan 的 `-h` 是「目标主机」参数（缺参会报错并以非零退出码退出），
            // 只有 `-help` 会无副作用地打印版本 banner（如 `Fscan 2.2.1 ...`）并以 0 退出。
            List.of("-help"),
            false,
            "SCANNER",
            output ->
                containsIgnoreCase(output, "fscan")
                    && (containsIgnoreCase(output, "扫描")
                        || containsIgnoreCase(output, "usage")
                        || containsIgnoreCase(output, "host")),
            "检测到的命令不是 fscan。当前仅检测版本，不默认执行。"),
        descriptor(
            "ProjectDiscovery httpx",
            scannerCandidates("HTTPX_PATH", "httpx"),
            List.of("-disable-update-check", "-version"),
            false,
            "SCANNER",
            this::isProjectDiscoveryHttpx,
            "检测到同名命令，但不是 ProjectDiscovery httpx。"),
        descriptorWithExtractor(
            "Metasploit",
            scannerCandidates("MSF_PATH", "msfconsole", "msfconsole.bat"),
            List.of("--version"),
            false,
            "SCANNER",
            output -> containsIgnoreCase(output, "metasploit"),
            "检测到的命令不是 MetasploitFramework。当前仅检测版本，不默认执行。",
            MSF_COMMAND_TIMEOUT,
            this::metasploitVersion),
        descriptorWithExtractor(
            "OWASP ZAP",
            zapCandidates(windows),
            List.of("-version"),
            false,
            "PROXY_SCANNER",
            output -> containsIgnoreCase(output, "zap") || containsIgnoreCase(output, "2.") || output.matches("(?s).*\\d+\\.\\d+.*"),
            "检测到的命令不是 OWASP ZAP。当前仅检测版本，不默认执行。",
            ZAP_COMMAND_TIMEOUT,
            this::zapVersion));
  }

  private boolean isWindows() {
    return System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("win");
  }

  private List<String> javaCandidates(boolean windows) {
    String executableName = windows ? "java.exe" : "java";
    String javaExecutable =
        Path.of(System.getProperty("java.home"), "bin", executableName).toString();
    return List.of(javaExecutable, "java");
  }

  private List<String> curlCandidates(boolean windows) {
    return paths(windows ? "curl.exe" : "curl", "curl");
  }

  private List<String> postgresqlCandidates(boolean windows) {
    List<String> candidates = new ArrayList<>();
    candidates.add(windows ? "psql.exe" : "psql");
    candidates.add("psql");
    return candidates;
  }

  private List<String> scannerCandidates(String envName, String... fallback) {
    List<String> candidates = new ArrayList<>();
    String explicit = System.getenv(envName);
    if (explicit != null && !explicit.isBlank()) {
      candidates.add(explicit.trim());
    }
    candidates.addAll(List.of(fallback));
    return candidates;
  }

  private List<String> zapCandidates(boolean windows) {
    LinkedHashSet<String> candidates = new LinkedHashSet<>();
    String explicit = System.getenv("ZAP_PATH");
    if (explicit != null && !explicit.isBlank() && !"zap".equalsIgnoreCase(explicit.trim())) {
      candidates.add(explicit.trim());
    }

    findZapInTools(candidates, windows);

    if (windows) {
      candidates.add("zap.bat");
      candidates.add("zap.exe");
      candidates.add("zaproxy.bat");
      candidates.add("zaproxy.exe");
      candidates.add("zap");
      candidates.add("zaproxy");
      String programFiles = System.getenv("ProgramFiles");
      if (programFiles != null && !programFiles.isBlank()) {
        candidates.add(Path.of(programFiles, "OWASP", "Zed Attack Proxy", "zap.bat").toString());
        candidates.add(Path.of(programFiles, "Zed Attack Proxy", "zap.bat").toString());
        candidates.add(Path.of(programFiles, "ZAP", "zap.bat").toString());
      }
      String programFilesX86 = System.getenv("ProgramFiles(x86)");
      if (programFilesX86 != null && !programFilesX86.isBlank()) {
        candidates.add(Path.of(programFilesX86, "OWASP", "Zed Attack Proxy", "zap.bat").toString());
        candidates.add(Path.of(programFilesX86, "Zed Attack Proxy", "zap.bat").toString());
        candidates.add(Path.of(programFilesX86, "ZAP", "zap.bat").toString());
      }
    } else {
      candidates.add("zaproxy");
      candidates.add("zap.sh");
      candidates.add("zap");
    }
    return new ArrayList<>(candidates);
  }

  private void findZapInTools(LinkedHashSet<String> candidates, boolean windows) {
    List<Path> searchRoots = new ArrayList<>();
    Path toolsDir = toolsRoot();
    if (toolsDir != null) {
      searchRoots.add(toolsDir);
    }
    searchRoots.add(Path.of("tools"));
    searchRoots.add(Path.of("..", "tools"));
    searchRoots.add(Path.of("security-toolbox-web", "tools"));
    searchRoots.add(Path.of("..", "security-toolbox-web", "tools"));
    searchRoots.add(Path.of("security-toolbox-web", "desktop-release", "win-unpacked", "tools"));
    searchRoots.add(Path.of("..", "security-toolbox-web", "desktop-release", "win-unpacked", "tools"));
    if (windows) {
      searchRoots.add(Path.of("D:\\stbtools"));
      searchRoots.add(Path.of("D:\\tools"));
    }

    List<String> targetNames =
        windows ? List.of("zap.bat", "zap.exe", "zap.sh") : List.of("zap.sh", "zaproxy", "zap");

    for (Path root : searchRoots) {
      try {
        if (!Files.isDirectory(root)) {
          continue;
        }
        Path zapDir = root.resolve("zap");
        if (Files.isDirectory(zapDir)) {
          for (String name : targetNames) {
            Path direct = zapDir.resolve(name);
            if (Files.isRegularFile(direct)) {
              candidates.add(direct.toAbsolutePath().normalize().toString());
            }
          }
          try (var stream = Files.list(zapDir)) {
            stream
                .filter(Files::isDirectory)
                .forEach(
                    sub -> {
                      for (String name : targetNames) {
                        Path candidate = sub.resolve(name);
                        if (Files.isRegularFile(candidate)) {
                          candidates.add(candidate.toAbsolutePath().normalize().toString());
                        }
                      }
                    });
          } catch (Exception ignored) {
          }
        }
        try (var stream = Files.list(root)) {
          stream
              .filter(p -> Files.isDirectory(p) && p.getFileName().toString().toLowerCase(Locale.ROOT).contains("zap"))
              .forEach(
                  dir -> {
                    for (String name : targetNames) {
                      Path candidate = dir.resolve(name);
                      if (Files.isRegularFile(candidate)) {
                        candidates.add(candidate.toAbsolutePath().normalize().toString());
                      }
                    }
                  });
        } catch (Exception ignored) {
        }
      } catch (Exception ignored) {
      }
    }
  }

  private DependencyDescriptor descriptor(
      String name,
      List<String> candidates,
      List<String> arguments,
      boolean required,
      String category,
      Predicate<String> validator,
      String incompatibleMessage) {
    return new DependencyDescriptor(
        name, candidates, arguments, required, category, validator, incompatibleMessage, COMMAND_TIMEOUT, DependencyDetectionService::firstNonBlankLine, false);
  }

  private DependencyDescriptor descriptorWithExtractor(
      String name,
      List<String> candidates,
      List<String> arguments,
      boolean required,
      String category,
      Predicate<String> validator,
      String incompatibleMessage,
      Duration timeout,
      Function<String, String> versionExtractor) {
    return new DependencyDescriptor(
        name, candidates, arguments, required, category, validator, incompatibleMessage, timeout, versionExtractor, true);
  }

  private List<String> paths(String... values) {
    return List.of(values);
  }

  private List<String> npcapCandidates() {
    LinkedHashSet<String> candidates = new LinkedHashSet<>();
    candidates.add("NPFInstall.exe");
    candidates.add("npcap.sys");
    candidates.add("Npcap");
    String programFiles = System.getenv("ProgramFiles");
    if (programFiles != null && !programFiles.isBlank()) {
      candidates.add(Path.of(programFiles, "Npcap", "NPFInstall.exe").toString());
      candidates.add(Path.of(programFiles, "Npcap", "npcap.sys").toString());
    }
    String programFilesX86 = System.getenv("ProgramFiles(x86)");
    if (programFilesX86 != null && !programFilesX86.isBlank()) {
      candidates.add(Path.of(programFilesX86, "Npcap", "NPFInstall.exe").toString());
      candidates.add(Path.of(programFilesX86, "Npcap", "npcap.sys").toString());
    }
    String systemRoot = System.getenv("SystemRoot");
    if (systemRoot != null && !systemRoot.isBlank()) {
      candidates.add(Path.of(systemRoot, "System32", "drivers", "npcap.sys").toString());
    }
    return List.copyOf(candidates);
  }

  private boolean isProjectDiscoveryHttpx(String output) {
    return containsIgnoreCase(output, "projectdiscovery")
        || containsIgnoreCase(output, "current version")
        || containsIgnoreCase(output, "httpx version");
  }

  private boolean containsIgnoreCase(String value, String expected) {
    return value.toLowerCase(Locale.ROOT).contains(expected.toLowerCase(Locale.ROOT));
  }

  private String cleanOutput(String output) {
    if (output == null) {
      return "";
    }
    return ANSI_ESCAPE.matcher(output).replaceAll("").replace('\r', '\n').trim();
  }

  private String parseVersion(DependencyDescriptor descriptor, String output) {
    if (output == null || output.isBlank()) {
      return UNKNOWN_VERSION;
    }
    String extracted = descriptor.versionExtractor().apply(output);
    return extracted == null || extracted.isBlank() ? UNKNOWN_VERSION : extracted;
  }

  private static String firstNonBlankLine(String output) {
    return output.lines().map(String::trim).filter(line -> !line.isBlank()).findFirst().orElse(UNKNOWN_VERSION);
  }

  // Metasploit 的 msfconsole --version 会先打印一串 Ruby 弃用警告（第一行往往是
  // 长长的 gem 路径），真正的版本在 "Framework Version: x.y..." 那行。
  private String metasploitVersion(String output) {
    return output
        .lines()
        .map(String::trim)
        .filter(line -> containsIgnoreCase(line, "Framework Version"))
        .findFirst()
        .orElseGet(() -> firstNonBlankLine(output));
  }

  // ZAP 的 zap.bat -version 在 Windows 下可能包含批处理回显命令行，
  // 提取纯语义版本号行或从命令回显中提取 zap 版本。
  private String zapVersion(String output) {
    if (output == null || output.isBlank()) {
      return UNKNOWN_VERSION;
    }
    List<String> lines = output.lines().map(String::trim).toList();
    for (String line : lines) {
      if (line.isBlank() || line.startsWith("if exist") || line.contains(">") || line.startsWith("set ")) {
        continue;
      }
      if (line.matches("^\\d+\\.\\d+(\\.\\d+)?.*")) {
        return line;
      }
    }
    for (String line : lines) {
      if (containsIgnoreCase(line, "zap") && line.matches(".*\\d+\\.\\d+.*")) {
        Matcher matcher = Pattern.compile("\\b\\d+\\.\\d+(\\.\\d+)?\\b").matcher(line);
        if (matcher.find()) {
          return matcher.group();
        }
      }
    }
    return firstNonBlankLine(output);
  }

  private String zapVersionFromPath(String path) {
    if (path == null || path.isBlank()) {
      return UNKNOWN_VERSION;
    }
    Matcher matcher = Pattern.compile("(?i)zap[_-](\\d+\\.\\d+(\\.\\d+)?)").matcher(path);
    if (matcher.find()) {
      return matcher.group(1);
    }
    try {
      Path p = Path.of(path);
      Path parent = p.getParent();
      if (parent != null) {
        // 尝试检查同目录或父目录下的 zap-*.jar 或 .toolbox-source.json
        Path sourceJson = parent.resolve(".toolbox-source.json");
        if (!Files.isRegularFile(sourceJson) && parent.getParent() != null) {
          sourceJson = parent.getParent().resolve(".toolbox-source.json");
        }
        if (Files.isRegularFile(sourceJson)) {
          String content = Files.readString(sourceJson, StandardCharsets.UTF_8);
          Matcher jsonMatcher = Pattern.compile("\"version\"\\s*:\\s*\"([^\"]+)\"").matcher(content);
          if (jsonMatcher.find()) {
            return jsonMatcher.group(1);
          }
        }
        try (var stream = Files.list(parent)) {
          var jarVersion = stream
              .filter(Files::isRegularFile)
              .map(f -> f.getFileName().toString())
              .filter(name -> name.toLowerCase(Locale.ROOT).startsWith("zap-") && name.toLowerCase(Locale.ROOT).endsWith(".jar"))
              .findFirst();
          if (jarVersion.isPresent()) {
            Matcher jarMatcher = Pattern.compile("(?i)zap-(\\d+\\.\\d+(\\.\\d+)?)\\.jar").matcher(jarVersion.get());
            if (jarMatcher.find()) {
              return jarMatcher.group(1);
            }
          }
        }
      }
    } catch (Exception ignored) {
    }
    return UNKNOWN_VERSION;
  }

  private String sanitizePath(Path path) {
    String normalized = path.toAbsolutePath().normalize().toString();
    String userHome = System.getProperty("user.home", "");
    if (!userHome.isBlank() && normalized.regionMatches(true, 0, userHome, 0, userHome.length())) {
      normalized = "%USERPROFILE%" + normalized.substring(userHome.length());
    }
    return normalized.replaceAll("(?i)^([A-Z]:\\\\Users\\\\)[^\\\\]+", "$1***");
  }

  private enum DetectionStatus {
    AVAILABLE,
    MISSING,
    TIMEOUT,
    ERROR,
    INCOMPATIBLE
  }

  private record DependencyDescriptor(
      String name,
      List<String> candidates,
      List<String> arguments,
      boolean required,
      String category,
      Predicate<String> outputValidator,
      String incompatibleMessage,
      Duration timeout,
      Function<String, String> versionExtractor,
      boolean timeoutResolvesAsAvailable) {}

  private record CachedDetection(long createdAtNanos, SystemDependenciesResponse response) {}
}
