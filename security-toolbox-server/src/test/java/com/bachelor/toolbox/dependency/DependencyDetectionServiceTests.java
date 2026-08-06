package com.bachelor.toolbox.dependency;

import static org.assertj.core.api.Assertions.assertThat;

import com.bachelor.toolbox.dependency.CommandRunner.CommandResult;
import com.bachelor.toolbox.dependency.SystemDependenciesResponse.DependencyStatus;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class DependencyDetectionServiceTests {
  @Test
  void detectsAvailableAndIncompatibleCommandsAndSanitizesUserPath() {
    Path userTools = Path.of(System.getProperty("user.home"), "security-tools");
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
          assertThat(timeout).isEqualTo(Duration.ofSeconds(3));
          if (executable.getFileName().toString().startsWith("nmap")) {
            return CommandResult.completed(0, "Nmap version 7.99\n");
          }
          return CommandResult.completed(0, "httpx 0.28.1 - The next generation HTTP client\n");
        };

    SystemDependenciesResponse response = new DependencyDetectionService(locator, runner).detect();
    DependencyStatus nmap = find(response, "Nmap");
    DependencyStatus httpx = find(response, "ProjectDiscovery httpx");

    assertThat(response.dependencies()).hasSize(12);
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
            "ProjectDiscovery httpx",
            "OWASP ZAP");
    assertThat(find(response, "Afrog").status()).isEqualTo("MISSING");
    assertThat(find(response, "Xray").status()).isEqualTo("MISSING");
    assertThat(nmap.status()).isEqualTo("AVAILABLE");
    assertThat(nmap.version()).isEqualTo("Nmap version 7.99");
    assertThat(nmap.path())
        .startsWith("%USERPROFILE%")
        .doesNotContain(System.getProperty("user.name"));
    assertThat(httpx.status()).isEqualTo("INCOMPATIBLE");
    assertThat(httpx.message()).contains("不是 ProjectDiscovery httpx");
  }

  @Test
  void reportsTimeoutWithoutWaitingBeyondRunnerContract() {
    ExecutableLocator locator = locateCandidate("nuclei", Path.of("C:/tools/nuclei.exe"));
    CommandRunner runner = (executable, arguments, timeout) -> CommandResult.timeout("");

    DependencyStatus nuclei =
        find(new DependencyDetectionService(locator, runner).detect(), "Nuclei");

    assertThat(nuclei.status()).isEqualTo("TIMEOUT");
    assertThat(nuclei.version()).isEqualTo("unknown");
    assertThat(nuclei.message()).contains("3 秒");
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
        new DependencyDetectionService(
            locator, (executable, arguments, timeout) -> CommandResult.completed(0, "unused"));

    SystemDependenciesResponse first = service.detect();
    SystemDependenciesResponse second = service.detect();

    assertThat(second).isSameAs(first);
    assertThat(locateCalls).hasValue(12);
  }

  @Test
  void reportsCommandFailureWithoutLeakingRunnerDetails() {
    ExecutableLocator locator = locateCandidate("nmap", Path.of("C:/tools/nmap.exe"));
    CommandRunner runner =
        (executable, arguments, timeout) ->
            CommandResult.failed("CreateProcess failed for C:/secret/tool.exe");

    DependencyStatus nmap = find(new DependencyDetectionService(locator, runner).detect(), "Nmap");

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
            throw new IllegalStateException("C:/private/location");
          }
          return Optional.empty();
        };

    SystemDependenciesResponse response =
        new DependencyDetectionService(
                locator, (executable, arguments, timeout) -> CommandResult.completed(0, "unused"))
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
            "C:/Program Files/Npcap/NPFInstall.exe",
            Path.of("C:/Program Files/Npcap/NPFInstall.exe"));
    AtomicInteger commandCalls = new AtomicInteger();
    CommandRunner runner =
        (executable, arguments, timeout) -> {
          commandCalls.incrementAndGet();
          return CommandResult.completed(0, "unused");
        };

    DependencyStatus npcap =
        find(new DependencyDetectionService(locator, runner).detect(), "Npcap");

    assertThat(commandCalls).hasValue(0);
    assertThat(npcap.status()).isEqualTo("AVAILABLE");
    assertThat(npcap.version()).isEqualTo("unknown");
    assertThat(npcap.message()).isEqualTo("已检测到安装目录或启动文件。");
  }

  @Test
  void cleansVersionOutputAndPreservesExitCodeFailureStatus() {
    ExecutableLocator locator = locateCandidate("nuclei", Path.of("C:/tools/nuclei.exe"));
    CommandRunner runner =
        (executable, arguments, timeout) ->
            CommandResult.completed(7, "\u001B[31mNuclei v3.2.0\u001B[0m\r\nextra output");

    DependencyStatus nuclei =
        find(new DependencyDetectionService(locator, runner).detect(), "Nuclei");

    assertThat(nuclei.status()).isEqualTo("ERROR");
    assertThat(nuclei.version()).isEqualTo("Nuclei v3.2.0");
    assertThat(nuclei.message()).isEqualTo("版本命令执行失败，退出码 7。");
  }

  @Test
  void reportsIncompatibleOutputBeforeNonZeroExitCode() {
    ExecutableLocator locator = locateCandidate("httpx", Path.of("C:/tools/httpx.exe"));
    CommandRunner runner =
        (executable, arguments, timeout) -> CommandResult.completed(2, "generic HTTP client 1.0");

    DependencyStatus httpx =
        find(new DependencyDetectionService(locator, runner).detect(), "ProjectDiscovery httpx");

    assertThat(httpx.status()).isEqualTo("INCOMPATIBLE");
    assertThat(httpx.version()).isEqualTo("generic HTTP client 1.0");
    assertThat(httpx.message()).isEqualTo("检测到同名命令，但不是 ProjectDiscovery httpx。");
  }

  private ExecutableLocator locateCandidate(String expectedCandidate, Path executable) {
    return candidates ->
        candidates.contains(expectedCandidate) ? Optional.of(executable) : Optional.empty();
  }

  private DependencyStatus find(SystemDependenciesResponse response, String name) {
    return response.dependencies().stream()
        .filter(item -> item.name().equals(name))
        .findFirst()
        .orElseThrow();
  }
}
