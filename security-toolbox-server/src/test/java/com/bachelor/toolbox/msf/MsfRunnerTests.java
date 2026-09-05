package com.bachelor.toolbox.msf;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.bachelor.toolbox.common.ApiException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class MsfRunnerTests {
  @TempDir Path tempDir;

  @Test
  void requiresARealExecutableAndReportsToolUnavailable() {
    MsfRunner runner = new MsfRunner(candidates -> Optional.empty(), "msfconsole", 600);

    assertThatThrownBy(runner::requireExecutable)
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("未找到 msfconsole");
  }

  @Test
  void resolvesConfiguredExecutableCandidateFirst() throws Exception {
    Path exe = tempDir.resolve("msfconsole.bin");
    Files.createFile(exe);
    MsfRunner runner =
        new MsfRunner(
            candidates -> candidates.contains("msfconsole") ? Optional.of(exe) : Optional.empty(),
            "msfconsole",
            600);

    Path resolved = runner.requireExecutable();
    assertThat(resolved).isEqualTo(exe.toAbsolutePath().normalize());
  }
}