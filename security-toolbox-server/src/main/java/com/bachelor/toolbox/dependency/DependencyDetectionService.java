package com.bachelor.toolbox.dependency;

import com.bachelor.toolbox.dependency.CommandRunner.CommandResult;
import com.bachelor.toolbox.dependency.SystemDependenciesResponse.DependencyStatus;
import java.nio.file.Path;
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
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

@Service
public class DependencyDetectionService {
  private static final Logger log = LoggerFactory.getLogger(DependencyDetectionService.class);

  private static final int MAX_DETECTION_WORKERS = 12;
  private static final Duration COMMAND_TIMEOUT = Duration.ofMillis(3500);
  private static final Duration CACHE_TTL = Duration.ofSeconds(5);
  private static final Duration WORKER_SHUTDOWN_TIMEOUT = Duration.ofMillis(200);
  private static final String UNKNOWN_VERSION = "unknown";
  private static final Pattern ANSI_ESCAPE =
      Pattern.compile("\\x1B(?:[@-Z\\\\-_]|\\[[0-?]*[ -/]*[@-~])");

  private final ExecutableLocator locator;
  private final CommandRunner commandRunner;
  private final NmapExecutableResolver nmapExecutableResolver;
  private volatile CachedDetection cachedDetection;

  public DependencyDetectionService(
      ExecutableLocator locator,
      CommandRunner commandRunner,
      NmapExecutableResolver nmapExecutableResolver) {
    this.locator = locator;
    this.commandRunner = commandRunner;
    this.nmapExecutableResolver = nmapExecutableResolver;
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
            dependencies);
    cachedDetection = new CachedDetection(System.nanoTime(), response);
    return response;
  }

  public void detectStreaming(
      Consumer<DependencyStatus> onEach, Consumer<List<DependencyStatus>> onComplete) {
    List<DependencyDescriptor> descriptors = dependencyDescriptors();
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

    CommandResult result = commandRunner.run(executable, descriptor.arguments(), COMMAND_TIMEOUT);
    return evaluateVersionCommand(descriptor, safePath, result);
  }

  private DependencyStatus evaluateVersionCommand(
      DependencyDescriptor descriptor, String safePath, CommandResult result) {
    String output = cleanOutput(result.output());
    if (result.timedOut()) {
      return buildStatus(
          descriptor,
          DetectionStatus.TIMEOUT,
          parseVersion(output),
          safePath,
          String.format(Locale.ROOT, "版本检测超过 %.1f 秒，进程已终止。", COMMAND_TIMEOUT.toMillis() / 1000.0));
    }
    if (result.errorMessage() != null) {
      return buildStatus(descriptor, DetectionStatus.ERROR, null, safePath, "已找到，但无法执行版本检测。");
    }
    if (!output.isBlank() && !descriptor.outputValidator().test(output)) {
      return buildStatus(
          descriptor,
          DetectionStatus.INCOMPATIBLE,
          parseVersion(output),
          safePath,
          descriptor.incompatibleMessage());
    }
    if (result.exitCode() != 0) {
      return buildStatus(
          descriptor,
          DetectionStatus.ERROR,
          parseVersion(output),
          safePath,
          "版本命令执行失败，退出码 " + result.exitCode() + "。");
    }
    return buildStatus(
        descriptor, DetectionStatus.AVAILABLE, parseVersion(output), safePath, "可用。");
  }

  private DependencyStatus buildStatus(
      DependencyDescriptor descriptor,
      DetectionStatus status,
      String version,
      String path,
      String message) {
    return new DependencyStatus(
        descriptor.name(),
        status.name(),
        version,
        path,
        descriptor.required(),
        descriptor.category(),
        message.trim());
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
            "ProjectDiscovery httpx",
            scannerCandidates("HTTPX_PATH", "httpx"),
            List.of("-disable-update-check", "-version"),
            false,
            "SCANNER",
            this::isProjectDiscoveryHttpx,
            "检测到同名命令，但不是 ProjectDiscovery httpx。"),
        descriptor(
            "OWASP ZAP", zapCandidates(windows), List.of(), false, "PROXY_SCANNER", anyOutput, ""));
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
    if (!windows) {
      return List.of("zaproxy", "zap.sh");
    }
    return paths(
        "zap.exe",
        "zap.bat",
        "zaproxy");
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
        name, candidates, arguments, required, category, validator, incompatibleMessage);
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

  private String parseVersion(String output) {
    if (output == null || output.isBlank()) {
      return UNKNOWN_VERSION;
    }
    return output
        .lines()
        .map(String::trim)
        .filter(line -> !line.isBlank())
        .findFirst()
        .orElse(UNKNOWN_VERSION);
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
      String incompatibleMessage) {}

  private record CachedDetection(long createdAtNanos, SystemDependenciesResponse response) {}
}
