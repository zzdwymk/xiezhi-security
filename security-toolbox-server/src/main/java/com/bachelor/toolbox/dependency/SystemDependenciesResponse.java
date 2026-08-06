package com.bachelor.toolbox.dependency;

import java.util.List;

public record SystemDependenciesResponse(
    String os, String arch, List<DependencyStatus> dependencies) {
  public record DependencyStatus(
      String name,
      String status,
      String version,
      String path,
      boolean required,
      String category,
      String message) {}
}
