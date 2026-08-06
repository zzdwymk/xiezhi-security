package com.bachelor.toolbox.task;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.dependency.DependencyDetectionService;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.tool.SecurityTool;
import com.bachelor.toolbox.vulnerability.DetectionRule;
import com.bachelor.toolbox.vulnerability.DetectionRuleRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class TaskSnapshotService {
  private static final Logger log = LoggerFactory.getLogger(TaskSnapshotService.class);
  private static final String SNAPSHOT_FAILED_MESSAGE = "无法生成任务授权与执行环境快照，请稍后重试";

  private final ObjectMapper objectMapper;
  private final DetectionRuleRepository rules;
  private final DependencyDetectionService dependencies;
  private final Path nucleiTemplatesPath;

  public TaskSnapshotService(
      ObjectMapper objectMapper,
      DetectionRuleRepository rules,
      DependencyDetectionService dependencies,
      @Value("${toolbox.execution.nuclei-templates-path:${user.home}/nuclei-templates}")
          String path) {
    this.objectMapper = objectMapper;
    this.rules = rules;
    this.dependencies = dependencies;
    this.nucleiTemplatesPath = Path.of(path).toAbsolutePath().normalize();
  }

  public void assertCurrentMatches(SecurityTask task, AuthorizedTarget target, SecurityTool tool) {
    SecurityTask current = new SecurityTask();
    current.setToolCode(task.getToolCode());
    current.setRuleCode(task.getRuleCode());
    capture(current, target, tool);
    if (!targetSnapshotEquivalent(task.getTargetSnapshotJson(), current.getTargetSnapshotJson())
        || !Objects.equals(task.getAllowedPortsSnapshot(), current.getAllowedPortsSnapshot())
        || !Objects.equals(
            task.getAuthorizationStatementSnapshot(), current.getAuthorizationStatementSnapshot())
        || !Objects.equals(
            task.getAuthorizationValidFromSnapshot(), current.getAuthorizationValidFromSnapshot())
        || !Objects.equals(
            task.getAuthorizationExpiresAtSnapshot(), current.getAuthorizationExpiresAtSnapshot())
        || !Objects.equals(task.getToolVersionSnapshot(), current.getToolVersionSnapshot())
        || !Objects.equals(task.getRuleVersionSnapshot(), current.getRuleVersionSnapshot())
        || !Objects.equals(
            task.getNucleiTemplateHashSnapshot(), current.getNucleiTemplateHashSnapshot())) {
      throw new ApiException("任务创建后的授权、工具、规则或 Nuclei 模板已发生变化，请重新创建任务");
    }
  }

  private boolean targetSnapshotEquivalent(String left, String right) {
    try {
      ObjectNode a = (ObjectNode) objectMapper.readTree(left);
      ObjectNode b = (ObjectNode) objectMapper.readTree(right);
      a.remove("capturedAt");
      b.remove("capturedAt");
      return a.equals(b);
    } catch (Exception ex) {
      log.warn("比较任务目标快照失败", ex);
      return false;
    }
  }

  public void capture(SecurityTask task, AuthorizedTarget target, SecurityTool tool) {
    try {
      Instant capturedAt = Instant.now();
      task.setTargetSnapshotJson(
          objectMapper.writeValueAsString(
              Map.of(
                  "id",
                  target.getId(),
                  "name",
                  target.getName(),
                  "targetValue",
                  target.getTargetValue(),
                  "targetType",
                  target.getTargetType(),
                  "enabled",
                  target.isEnabled(),
                  "capturedAt",
                  capturedAt)));
      task.setAllowedPortsSnapshot(target.getAllowedPorts());
      task.setAuthorizationStatementSnapshot(target.getAuthorizationNote());
      task.setAuthorizationValidFromSnapshot(target.getAuthorizationValidFrom());
      task.setAuthorizationExpiresAtSnapshot(target.getAuthorizationExpiresAt());
      task.setToolVersionSnapshot(resolveToolVersion(tool));
      task.setRuleVersionSnapshot(resolveRuleVersion(task.getRuleCode()));
      task.setNucleiTemplateHashSnapshot(
          "nuclei_scan".equals(task.getToolCode()) ? nucleiTemplateSetHash() : null);
      task.setSnapshotCapturedAt(capturedAt);
      task.setSnapshotSchemaVersion("1");
      String integrity =
          objectMapper.writeValueAsString(
              Map.of(
                  "target",
                  task.getTargetSnapshotJson(),
                  "ports",
                  task.getAllowedPortsSnapshot(),
                  "statement",
                  task.getAuthorizationStatementSnapshot(),
                  "validFrom",
                  String.valueOf(task.getAuthorizationValidFromSnapshot()),
                  "expiresAt",
                  String.valueOf(task.getAuthorizationExpiresAtSnapshot()),
                  "toolVersion",
                  String.valueOf(task.getToolVersionSnapshot()),
                  "ruleVersion",
                  String.valueOf(task.getRuleVersionSnapshot()),
                  "nucleiHash",
                  String.valueOf(task.getNucleiTemplateHashSnapshot()),
                  "schema",
                  "1"));
      task.setAuthorizationSnapshotHash(sha256(integrity.getBytes(StandardCharsets.UTF_8)));
    } catch (Exception ex) {
      log.error("生成任务授权与执行环境快照失败，taskId={}，toolCode={}", task.getId(), task.getToolCode(), ex);
      throw new ApiException(SNAPSHOT_FAILED_MESSAGE);
    }
  }

  private String resolveToolVersion(SecurityTool tool) {
    String dependencyName =
        switch (tool.code()) {
          case "nmap_service_scan" -> "Nmap";
          case "nuclei_scan" -> "Nuclei";
          default -> null;
        };
    if (dependencyName != null) {
      return dependencies.detect().dependencies().stream()
          .filter(item -> dependencyName.equals(item.name()))
          .findFirst()
          .map(item -> item.version() == null ? item.status() : item.version())
          .orElse("unknown");
    }
    String appVersion = TaskSnapshotService.class.getPackage().getImplementationVersion();
    return (appVersion == null ? "development" : appVersion)
        + "/"
        + tool.getClass().getSimpleName();
  }

  private String resolveRuleVersion(String ruleCode) throws Exception {
    if (ruleCode == null || ruleCode.isBlank()) {
      return null;
    }
    DetectionRule rule =
        rules.findByRuleCode(ruleCode)
            .orElseThrow(() -> new ApiException("检测规则不存在"));
    String canonical =
        objectMapper.writeValueAsString(
            Map.of(
                "ruleCode",
                rule.getRuleCode(),
                "vulnerabilityCode",
                rule.getVulnerabilityCode(),
                "name",
                rule.getName(),
                "toolCode",
                rule.getToolCode(),
                "targetType",
                rule.getTargetType(),
                "riskLevel",
                rule.getRiskLevel(),
                "parametersJson",
                rule.getParametersJson(),
                "enabled",
                rule.isEnabled()));
    return sha256(canonical.getBytes(StandardCharsets.UTF_8));
  }

  private String nucleiTemplateSetHash() throws Exception {
    if (!Files.isDirectory(nucleiTemplatesPath)) {
      return "unavailable";
    }
    List<Path> roots =
        List.of("http/exposures", "http/misconfiguration", "http/technologies", "ssl").stream()
            .map(nucleiTemplatesPath::resolve)
            .filter(Files::isDirectory)
            .toList();
    StringBuilder manifest = new StringBuilder();
    for (Path root : roots) {
      try (var files = Files.walk(root)) {
        files
            .filter(Files::isRegularFile)
            .filter(p -> p.toString().endsWith(".yaml") || p.toString().endsWith(".yml"))
            .sorted(Comparator.comparing(p -> nucleiTemplatesPath.relativize(p).toString()))
            .forEach(
                p -> {
                  try {
                    manifest
                        .append(nucleiTemplatesPath.relativize(p).toString().replace('\\', '/'))
                        .append('\0')
                        .append(sha256(Files.readAllBytes(p)))
                        .append('\n');
                  } catch (Exception ex) {
                    throw new IllegalStateException(ex);
                  }
                });
      }
    }
    return sha256(manifest.toString().getBytes(StandardCharsets.UTF_8));
  }

  private String sha256(byte[] value) throws Exception {
    return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value));
  }
}
