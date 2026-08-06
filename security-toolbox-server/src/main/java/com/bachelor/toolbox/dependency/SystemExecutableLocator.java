package com.bachelor.toolbox.dependency;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import org.springframework.stereotype.Component;

@Component
public class SystemExecutableLocator implements ExecutableLocator {
  private final boolean windows =
      System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("win");

  @Override
  public Optional<Path> find(List<String> candidates) {
    for (String candidate : candidates) {
      Optional<Path> resolved = resolve(candidate);
      if (resolved.isPresent()) {
        return resolved;
      }
    }
    return Optional.empty();
  }

  private Optional<Path> resolve(String candidate) {
    Path candidatePath = Path.of(candidate);
    if (candidatePath.isAbsolute() || candidate.contains("/") || candidate.contains("\\")) {
      return resolveExplicitPath(candidatePath);
    }

    return resolveFromSystemPath(candidate);
  }

  private Optional<Path> resolveExplicitPath(Path candidatePath) {
    if (!Files.exists(candidatePath)) {
      return Optional.empty();
    }
    return Optional.of(candidatePath.toAbsolutePath().normalize());
  }

  private Optional<Path> resolveFromSystemPath(String candidate) {
    String pathValue = System.getenv("PATH");
    if (pathValue == null || pathValue.isBlank()) {
      return Optional.empty();
    }
    for (String directory : pathValue.split(java.io.File.pathSeparator)) {
      if (directory.isBlank()) {
        continue;
      }
      for (String fileName : executableNames(candidate)) {
        Path path = Path.of(directory, fileName);
        if (Files.isRegularFile(path) && (windows || Files.isExecutable(path))) {
          return Optional.of(path.toAbsolutePath().normalize());
        }
      }
    }
    return Optional.empty();
  }

  private List<String> executableNames(String candidate) {
    if (!windows
        || candidate.lastIndexOf('.') > candidate.lastIndexOf(java.io.File.separatorChar)) {
      return List.of(candidate);
    }
    Set<String> names = new LinkedHashSet<>();
    names.add(candidate);
    String pathExt = System.getenv().getOrDefault("PATHEXT", ".EXE;.CMD;.BAT;.COM");
    for (String extension : pathExt.split(";")) {
      if (extension.isBlank()) {
        continue;
      }
      names.add(candidate + extension.toLowerCase(Locale.ROOT));
      names.add(candidate + extension.toUpperCase(Locale.ROOT));
    }
    return new ArrayList<>(names);
  }
}
