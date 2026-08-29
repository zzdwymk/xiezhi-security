package com.bachelor.toolbox.dependency;

import static org.assertj.core.api.Assertions.assertThat;

import com.bachelor.toolbox.dependency.CommandRunner.CommandResult;
import com.bachelor.toolbox.dependency.SystemDependenciesResponse.DependencyStatus;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

class DependencyDetectionServiceTests {
  @Test
  void detectsAvailableAndIncompatibleCommandsAndSanitizesUserPath() {
    Path userTools = Path.of("test-data", "security-tools");
    ExecutableLocator locator =
        candidates -> {
          if (candidates.stream().anyMatch(value -> value.equals("nmap"))) {
            return Optional.of(userTools.resolve("nmap.exe"));
          }
          if (candidates.stream().anyMatch(value -> value.equals("httpx"))) {
            return Optional.of(userTools.resolve("httpx.exe"));
          }
          return Optional.empty();
        };
    CommandRunner runner =
        (executable, arguments, timeout) -> {
          assertThat(timeout).isEqualTo(Duration.ofMillis(3500));
          if (executable.getFileName().toString().startsWith("nmap")) {
            return CommandResult.completed(0, "Nmap version 7.99\n");
          }
          return CommandResult.completed(0, "httpx 0.28.1 - The next generation HTTP client\n");
        };

    SystemDependenciesResponse response = service(locator, runner).detect();
    DependencyStatus nmap = find(response, "Nmap");
    DependencyStatus httpx = find(response, "ProjectDiscovery httpx");

    assertThat(response.dependencies()).hasSize(13);
    assertThat(response.dependencies())
        .extracting(DependencyStatus::name)
        .containsExactly(
            "Java",
            "Nmap",
            "Npcap",
            "OpenSSL",
            "curl",
            "Python",
            "PostgreSQL",
            "Nuclei",
            "Afrog",
            "Xray",
            "fscan",
            "ProjectDiscovery httpx",
            "OWASP ZAP");
    assertThat(find(response, "Afrog").status()).isEqualTo("MISSING");
    assertThat(find(response, "Xray").status()).isEqualTo("MISSING");
    assertThat(nmap.status()).isEqualTo("AVAILABLE");
    assertThat(nmap.version()).isEqualTo("Nmap version 7.99");
    assertThat(nmap.path()).contains("security-tools").doesNotContain(System.getProperty("user.name"));
    assertThat(httpx.status()).isEqualTo("INCOMPATIBLE");
    assertThat(httpx.message()).contains("不是 ProjectDiscovery httpx");
  }

  @Test
  void usesConfiguredNmapExecutableForPreflight() {
    String configuredExecutable = "test-data/tools/nmap";
    Path resolvedExecutable = Path.of(configuredExecutable).normalize();
    Path expectedTail = Path.of("test-data", "tools", "nmap");
    AtomicReference<List<String>> receivedCandidates = new AtomicReference<>();
    ExecutableLocator locator =
        candidates -> {
          if (candidates.contains(configuredExecutable)) {
            receivedCandidates.set(candidates);
            return Optional.of(resolvedExecutable);
          }
          return Optional.empty();
        };
    CommandRunner runner =
        (executable, arguments, timeout) -> {
          assertThat(executable).isEqualTo(resolvedExecutable);
          return CommandResult.completed(0, "Nmap version 7.99");
        };
    NmapExecutableResolver resolver =
        new NmapExecutableResolver(locator, configuredExecutable);

    DependencyStatus nmap =
        find(new DependencyDetectionService(locator, runner, resolver).detect(), "Nmap");

    assertThat(receivedCandidates.get())
        .containsExactly(
            configuredExecutable,
            "nmap",
            "nmap.exe");
    assertThat(nmap.status()).isEqualTo("AVAILABLE");
    assertThat(nmap.path())
        .satisfies(
            path ->
                assertThat(Path.of(path).normalize().toString())
                    .endsWith(expectedTail.normalize().toString())
                    .doesNotContain(".."));
  }

  @Test
  void reportsTimeoutWithoutWaitingBeyondRunnerContract() {
    ExecutableLocator locator = locateCandidate("nuclei", Path.of("test-data/tools/nuclei"));
    CommandRunner runner = (executable, arguments, timeout) -> CommandResult.timeout("");

    DependencyStatus nuclei =
        find(service(locator, runner).detect(), "Nuclei");

    assertThat(nuclei.status()).isEqualTo("TIMEOUT");
    assertThat(nuclei.version()).isEqualTo("unknown");
    assertThat(nuclei.message()).contains("3.5 秒");
  }

  @Test
  void cachesCompleteResponseForFiveSecondWindow() {
    AtomicInteger locateCalls = new AtomicInteger();
    ExecutableLocator locator =
        candidates -> {
          locateCalls.incrementAndGet();
          return Optional.empty();
        };
    DependencyDetectionService service =
        service(locator, (executable, arguments, timeout) -> CommandResult.completed(0, "unused"));

    SystemDependenciesResponse first = service.detect();
    SystemDependenciesResponse second = service.detect();

    assertThat(second).isSameAs(first);
    assertThat(locateCalls).hasValue(13);
  }

  @Test
  void forcedRefreshBypassesRecentCachedResponse() {
    AtomicInteger locateCalls = new AtomicInteger();
    ExecutableLocator locator =
        candidates -> {
          locateCalls.incrementAndGet();
          return Optional.empty();
        };
    DependencyDetectionService service =
        service(locator, (executable, arguments, timeout) -> CommandResult.completed(0, "unused"));

    SystemDependenciesResponse first = service.detect();
    SystemDependenciesResponse refreshed = service.detect(true);

    assertThat(refreshed).isNotSameAs(first);
    assertThat(locateCalls).hasValue(26);
  }

  @Test
  void disablesAfrogUpdateCheckDuringVersionProbe() {
    ExecutableLocator locator = locateCandidate("afrog", Path.of("test-data/tools/afrog"));
    CommandRunner runner =
        (executable, arguments, timeout) -> {
          assertThat(arguments).containsExactly("-disable-update-check", "-version");
          return CommandResult.completed(0, "Afrog 3.5.6");
        };

    DependencyStatus afrog =
        find(service(locator, runner).detect(), "Afrog");

    assertThat(afrog.status()).isEqualTo("AVAILABLE");
    assertThat(afrog.version()).isEqualTo("Afrog 3.5.6");
  }

  @Test
  void disablesNetworkUpdateChecksForProjectDiscoveryScanners() {
    ExecutableLocator locator =
        candidates -> {
          if (candidates.contains("nuclei")) return Optional.of(Path.of("test-data/tools/nuclei"));
          if (candidates.contains("httpx")) return Optional.of(Path.of("test-data/tools/httpx"));
          return Optional.empty();
        };
    CommandRunner runner =
        (executable, arguments, timeout) -> {
          assertThat(arguments).containsExactly("-disable-update-check", "-version");
          return executable.getFileName().toString().startsWith("nuclei")
              ? CommandResult.completed(0, "Nuclei Engine Version: 3.5.0")
              : CommandResult.completed(0, "Current Version: v1.7.1 httpx");
        };

    SystemDependenciesResponse response = service(locator, runner).detect();

    assertThat(find(response, "Nuclei").status()).isEqualTo("AVAILABLE");
    assertThat(find(response, "ProjectDiscovery httpx").status()).isEqualTo("AVAILABLE");
  }

  @Test
  void reportsCommandFailureWithoutLeakingRunnerDetails() {
    ExecutableLocator locator = locateCandidate("nmap", Path.of("test-data/tools/nmap"));
    CommandRunner runner =
        (executable, arguments, timeout) ->
            CommandResult.failed("CreateProcess failed for test-data/secret/tool");

    DependencyStatus nmap = find(service(locator, runner).detect(), "Nmap");

    assertThat(nmap.status()).isEqualTo("ERROR");
    assertThat(nmap.version()).isNull();
    assertThat(nmap.message())
        .isEqualTo("已找到，但无法执行版本检测。")
        .doesNotContain("CreateProcess", "secret");
  }

  @Test
  void isolatesUnexpectedFailureToAffectedDependency() {
    ExecutableLocator locator =
        candidates -> {
          if (candidates.contains("nmap")) {
            throw new IllegalStateException("test-data/private/location");
          }
          return Optional.empty();
        };

    SystemDependenciesResponse response =
        service(locator, (executable, arguments, timeout) -> CommandResult.completed(0, "unused"))
            .detect();

    DependencyStatus nmap = find(response, "Nmap");
    assertThat(nmap.status()).isEqualTo("ERROR");
    assertThat(nmap.path()).isNull();
    assertThat(nmap.message())
        .isEqualTo("依赖检测执行失败。")
        .doesNotContain("private", "IllegalStateException");
    assertThat(find(response, "Nuclei").status()).isEqualTo("MISSING");
  }

  @Test
  void skipsVersionCommandForPathOnlyDependency() {
    ExecutableLocator locator =
        locateCandidate(
            "NPFInstall.exe",
            Path.of("test-data/tools/NPFInstall.exe"));
    AtomicInteger commandCalls = new AtomicInteger();
    CommandRunner runner =
        (executable, arguments, timeout) -> {
          commandCalls.incrementAndGet();
          return CommandResult.completed(0, "unused");
        };

    DependencyStatus npcap =
        find(service(locator, runner).detect(), "Npcap");

    assertThat(commandCalls).hasValue(0);
    assertThat(npcap.status()).isEqualTo("AVAILABLE");
    assertThat(npcap.version()).isEqualTo("unknown");
    assertThat(npcap.message()).isEqualTo("已检测到安装目录或启动文件。");
  }

  @Test
  void cleansVersionOutputAndPreservesExitCodeFailureStatus() {
    ExecutableLocator locator = locateCandidate("nuclei", Path.of("test-data/tools/nuclei"));
    CommandRunner runner =
        (executable, arguments, timeout) ->
            CommandResult.completed(7, "\u001B[31mNuclei v3.2.0\u001B[0m\r\nextra output");

    DependencyStatus nuclei =
        find(service(locator, runner).detect(), "Nuclei");

    assertThat(nuclei.status()).isEqualTo("ERROR");
    assertThat(nuclei.version()).isEqualTo("Nuclei v3.2.0");
    assertThat(nuclei.message()).isEqualTo("版本命令执行失败，退出码 7。");
  }

  @Test
  void reportsIncompatibleOutputBeforeNonZeroExitCode() {
    ExecutableLocator locator = locateCandidate("httpx", Path.of("test-data/tools/httpx"));
    CommandRunner runner =
        (executable, arguments, timeout) -> CommandResult.completed(2, "generic HTTP client 1.0");

    DependencyStatus httpx =
        find(service(locator, runner).detect(), "ProjectDiscovery httpx");

    assertThat(httpx.status()).isEqualTo("INCOMPATIBLE");
    assertThat(httpx.version()).isEqualTo("generic HTTP client 1.0");
    assertThat(httpx.message()).isEqualTo("检测到同名命令，但不是 ProjectDiscovery httpx。");
  }

  private ExecutableLocator locateCandidate(String expectedCandidate, Path executable) {
    return candidates ->
        candidates.contains(expectedCandidate) ? Optional.of(executable) : Optional.empty();
  }

  private DependencyDetectionService service(ExecutableLocator locator, CommandRunner runner) {
    return new DependencyDetectionService(
        locator, runner, new NmapExecutableResolver(locator, "nmap"));
  }

  private DependencyStatus find(SystemDependenciesResponse response, String name) {
    return response.dependencies().stream()
        .filter(item -> item.name().equals(name))
        .findFirst()
        .orElseThrow();
  }
}
