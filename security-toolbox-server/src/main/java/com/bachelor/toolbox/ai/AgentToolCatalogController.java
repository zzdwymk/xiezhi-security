package com.bachelor.toolbox.ai;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Exposes the authoritative tool catalog to the Python runtime.
 *
 * <p>The runtime uses this to describe tools to the model. It is intentionally a plain read-only
 * GET with no side effects: it carries no authorization decision and grants nothing. The real
 * enforcement stays in {@code CapabilityGate} / {@code AiTaskDispatchService} at execution time —
 * knowing a tool exists has never been, and must never become, permission to run it.
 */
@RestController
@RequestMapping("/api/ai/agent")
public class AgentToolCatalogController {

  @GetMapping("/catalog")
  public Map<String, Object> catalog() {
    Map<String, Object> value = new LinkedHashMap<>();
    value.put("revision", "java-authoritative-v1");
    value.put("executableCodes", AiToolCatalog.EXECUTABLE_CODES);
    value.put("runtimeCodes", AiToolCatalog.RUNTIME_CODES);
    value.put("tools", AiToolCatalog.descriptors());
    // Stated explicitly so a reader cannot mistake the catalog for an execution permit.
    value.put(
        "note",
        "本清单只描述工具是否存在与参数形状，不构成执行许可；任何调用都要经四层护栏与管理员确认");
    return value;
  }

  /** Codes only, for lightweight drift checks. */
  @GetMapping("/catalog/codes")
  public Map<String, Object> codes() {
    return Map.of(
        "runtimeCodes", List.copyOf(AiToolCatalog.RUNTIME_CODES),
        "executableCodes", List.copyOf(AiToolCatalog.EXECUTABLE_CODES));
  }
}
