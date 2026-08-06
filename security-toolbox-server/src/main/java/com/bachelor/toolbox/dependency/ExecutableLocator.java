package com.bachelor.toolbox.dependency;

import java.nio.file.Path;
import java.util.List;
import java.util.Optional;

public interface ExecutableLocator {
  Optional<Path> find(List<String> candidates);
}
