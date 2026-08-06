package com.bachelor.toolbox.dependency;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ProcessCommandRunnerTests {
  @TempDir Path tempDirectory;

  @Test
  void hidesProcessStartupDetailsFromVisibleResult() {
    Path missingExecutable = tempDirectory.resolve("credential-secret-tool.exe");

    CommandRunner.CommandResult result =
        new ProcessCommandRunner()
            .run(missingExecutable, List.of("--version"), Duration.ofSeconds(1));

    assertThat(result.exitCode()).isEqualTo(-1);
    assertThat(result.output()).isEmpty();
    assertThat(result.timedOut()).isFalse();
    assertThat(result.errorMessage())
        .isEqualTo("外部命令执行失败，请稍后重试")
        .doesNotContain("credential-secret-tool", "IOException", "CreateProcess");
  }
}
