package com.bachelor.toolbox.dependency;

import java.nio.file.Path;
import java.time.Duration;
import java.util.List;

public interface CommandRunner {
  CommandResult run(Path executable, List<String> arguments, Duration timeout);

  record CommandResult(int exitCode, String output, boolean timedOut, String errorMessage) {
    static CommandResult completed(int exitCode, String output) {
      return new CommandResult(exitCode, output, false, null);
    }

    static CommandResult timeout(String output) {
      return new CommandResult(-1, output, true, null);
    }

    static CommandResult failed(String message) {
      return new CommandResult(-1, "", false, message);
    }
  }
}
