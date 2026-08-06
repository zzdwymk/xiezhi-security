package com.bachelor.toolbox.tool;

import java.util.List;
import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/tools")
public class ToolController {
  private final SecurityToolRegistry registry;

  public ToolController(SecurityToolRegistry registry) {
    this.registry = registry;
  }

  @GetMapping
  public List<Map<String, String>> list() {
    return registry.all().stream()
        .map(
            tool ->
                Map.of(
                    "code", tool.code(),
                    "name", tool.displayName(),
                    "description", tool.description()))
        .toList();
  }
}
