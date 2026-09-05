package com.bachelor.toolbox.msf;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.common.ProcessEnvironmentSanitizer;
import com.bachelor.toolbox.dependency.ExecutableLocator;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.springframework.stereotype.Component;

/** 运行本机 {@code msfconsole} 子进程的最小封装，供模块枚举与单/多模块执行复用。 */
@Component
public class MsfRunner {
  private static final int MAX_OUTPUT_BYTES = 2 * 1024 * 1024;

  private final ExecutableLocator locator;
  private final String configuredExecutable;
  private final long timeoutSeconds;

  public MsfRunner(
      ExecutableLocator locator,
      @org.springframework.beans.factory.annotation.Value(
              "${toolbox.execution.msf-path:msfconsole}")
          String configuredExecutable,
      @org.springframework.beans.factory.annotation.Value(
          "${toolbox.execution.msf-timeout-seconds:600}")
          long timeoutSeconds) {
    this.locator = locator;
    this.configuredExecutable = configuredExecutable;
    this.timeoutSeconds = timeoutSeconds;
  }

  public Path requireExecutable() {
    Path executable =
        locator
            .find(candidates())
            .orElseThrow(
                () -> new ApiException("未找到 msfconsole，请先安装 MetasploitFramework"));
    if (!Files.isRegularFile(executable)) {
      throw new ApiException("未找到已配置的 msfconsole 可执行文件");
    }
    return executable.toAbsolutePath().normalize();
  }

  public String run(String script, List<String> extraArgs) throws Exception {
    Path executable = requireExecutable();
    List<String> command = new java.util.ArrayList<>();
    command.add(executable.toString());
    command.add("-q");
    command.addAll(extraArgs);
    command.add("-x");
    command.add(script);
    ProcessBuilder builder =
        ProcessEnvironmentSanitizer.sanitize(new ProcessBuilder(command));
    builder.redirectErrorStream(true);
    Process process = builder.start();
    try {
      ExecutorService reader = Executors.newSingleThreadExecutor();
      Future<String> output = reader.submit(() -> readLimited(process.getInputStream()));
      try {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(timeoutSeconds);
        while (!process.waitFor(250, TimeUnit.MILLISECONDS)) {
          if (System.nanoTime() >= deadline) {
            process.destroyForcibly();
            process.waitFor(5, TimeUnit.SECONDS);
            throw new ApiException("msfconsole 执行超过 " + timeoutSeconds + " 秒，已强制终止");
          }
        }
        String stdout = output.get(10, TimeUnit.SECONDS);
        if (process.exitValue() != 0) {
          throw new ApiException(
              "msfconsole 执行失败，退出码 " + process.exitValue() + "：" + abbreviate(stdout, 300));
        }
        return stdout;
      } finally {
        reader.shutdownNow();
      }
    } finally {
      if (process.isAlive()) process.destroyForcibly();
    }
  }

  private List<String> candidates() {
    Set<String> candidates = new LinkedHashSet<>();
    if (configuredExecutable != null && !configuredExecutable.isBlank()) {
      candidates.add(configuredExecutable.trim());
    }
    candidates.add("msfconsole");
    candidates.add("msfconsole.bat");
    return List.copyOf(candidates);
  }

  private String readLimited(InputStream input) throws Exception {
    byte[] data = input.readNBytes(MAX_OUTPUT_BYTES + 1);
    if (data.length > MAX_OUTPUT_BYTES) {
      throw new ApiException("msfconsole 输出超过安全大小限制");
    }
    return new String(data, StandardCharsets.UTF_8);
  }

  private String abbreviate(String value, int max) {
    String clean = value == null ? "" : value.replaceAll("\\s+", " ").trim();
    return clean.length() <= max ? clean : clean.substring(0, max) + "…";
  }
}