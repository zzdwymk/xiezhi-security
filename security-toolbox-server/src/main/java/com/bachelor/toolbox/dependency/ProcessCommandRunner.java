package com.bachelor.toolbox.dependency;

import com.bachelor.toolbox.common.ProcessEnvironmentSanitizer;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Component
public class ProcessCommandRunner implements CommandRunner {
  private static final Logger log = LoggerFactory.getLogger(ProcessCommandRunner.class);
  private static final int MAX_CAPTURE_BYTES = 64 * 1024;
  private static final String EXECUTION_FAILED_MESSAGE = "外部命令执行失败，请稍后重试";

  @Override
  public CommandResult run(Path executable, List<String> arguments, Duration timeout) {
    List<String> command = new ArrayList<>(arguments.size() + 1);
    command.add(executable.toString());
    command.addAll(arguments);

    Process process = null;
    ExecutorService reader = Executors.newSingleThreadExecutor();
    Future<String> output = null;
    try {
      ProcessBuilder builder = new ProcessBuilder(command).redirectErrorStream(true);
      process = ProcessEnvironmentSanitizer.sanitize(builder).start();
      InputStream processOutput = process.getInputStream();
      output = reader.submit(() -> readOutput(processOutput));
      if (!process.waitFor(timeout.toMillis(), TimeUnit.MILLISECONDS)) {
        process.destroyForcibly();
        process.waitFor(150, TimeUnit.MILLISECONDS);
        return CommandResult.timeout(readFinishedOutput(output));
      }
      return CommandResult.completed(process.exitValue(), output.get(150, TimeUnit.MILLISECONDS));
    } catch (Exception ex) {
      log.error("执行外部命令失败，executable={}", executable, ex);
      return CommandResult.failed(EXECUTION_FAILED_MESSAGE);
    } finally {
      if (process != null && process.isAlive()) {
        process.destroyForcibly();
      }
      if (output != null && !output.isDone()) {
        output.cancel(true);
      }
      reader.shutdownNow();
    }
  }

  private String readOutput(InputStream input) throws IOException {
    ByteArrayOutputStream captured = new ByteArrayOutputStream();
    byte[] buffer = new byte[2048];
    int total = 0;
    int read;
    while ((read = input.read(buffer)) != -1) {
      if (total < MAX_CAPTURE_BYTES) {
        int copy = Math.min(read, MAX_CAPTURE_BYTES - total);
        captured.write(buffer, 0, copy);
        total += copy;
      }
    }
    return captured.toString(Charset.defaultCharset());
  }

  private String readFinishedOutput(Future<String> output) {
    if (output == null) {
      return "";
    }
    try {
      return output.get(100, TimeUnit.MILLISECONDS);
    } catch (Exception ex) {
      log.warn("读取外部命令输出失败", ex);
      return "";
    }
  }
}
