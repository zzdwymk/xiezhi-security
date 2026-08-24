package com.bachelor.toolbox.dependency;

import java.nio.file.Path;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class NmapExecutableResolver {
  private static final List<String> FALLBACK_CANDIDATES =
      List.of(
          "nmap",
          "nmap.exe");

  private final ExecutableLocator locator;
  private final String configuredExecutable;

  public NmapExecutableResolver(
      ExecutableLocator locator,
      @Value("${toolbox.execution.nmap-path:nmap}") String configuredExecutable) {
    this.locator = locator;
    this.configuredExecutable = configuredExecutable;
  }

  public Optional<Path> find() {
    return locator.find(candidates());
  }

  List<String> candidates() {
    Set<String> candidates = new LinkedHashSet<>();
    if (configuredExecutable != null && !configuredExecutable.isBlank()) {
      candidates.add(configuredExecutable.trim());
    }
    candidates.addAll(FALLBACK_CANDIDATES);
    return List.copyOf(candidates);
  }
}
