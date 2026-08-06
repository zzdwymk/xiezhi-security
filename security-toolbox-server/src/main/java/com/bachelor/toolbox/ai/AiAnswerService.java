package com.bachelor.toolbox.ai;

import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.finding.Finding;
import com.bachelor.toolbox.finding.FindingRepository;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.TargetService;
import com.bachelor.toolbox.project.AssessmentProjectService;
import com.bachelor.toolbox.task.SecurityTask;
import com.bachelor.toolbox.task.SecurityTaskRepository;
import com.fasterxml.jackson.databind.ObjectMapper;import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;
import org.springframework.stereotype.Service;

@Service
public class AiAnswerService {
  private static final int MAX_TASKS = 20;
  private static final int MAX_FINDING_DETAILS = 50;
  private static final int MAX_MODEL_CONTEXT_CHARS = 40_000;
  private static final Set<String> TERMINAL_STATUSES =
      Set.of("SUCCESS", "FAILED", "REJECTED", "CANCELLED");
  private static final List<String> SEVERITY_ORDER =
      List.of("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO");

  private final TargetService targetService;
  private final AssessmentProjectService projectService;
  private final SecurityTaskRepository taskRepository;
  private final FindingRepository findingRepository;
  private final AuditService auditService;
  private final ObjectMapper objectMapper;
  private final AiModelClient modelClient;

  public AiAnswerService(
      TargetService targetService,
      AssessmentProjectService projectService,
      SecurityTaskRepository taskRepository,
      FindingRepository findingRepository,
      AuditService auditService,
      ObjectMapper objectMapper,
      AiModelClient modelClient) {
    this.targetService = targetService;
    this.projectService = projectService;
    this.taskRepository = taskRepository;
    this.findingRepository = findingRepository;
    this.auditService = auditService;
    this.objectMapper = objectMapper;
    this.modelClient = modelClient;
  }
  public AiAnswerResponse answer(AiAnswerRequest request) {
    try {
      projectService.validateProjectTargetMembership(request.projectId(), request.targetId());
      AuthorizedTarget target = targetService.get(request.targetId());
      List<Long> requestedIds = validateTaskIds(request.taskIds());
      List<SecurityTask> tasks = loadAuthorizedTerminalTasks(target, request.projectId(), requestedIds);      List<Finding> findings =
          findingRepository.findAllByTaskIdInOrderByCreatedAtAsc(requestedIds).stream()
              .filter(finding -> Objects.equals(finding.getTargetId(), target.getId()))
              .toList();

      String provider = "local-rule-fallback";
      String answer = localAnswer(request.prompt(), tasks, findings);
      if (modelClient.enabled()) {
        try {
          answer = callModel(target, request.prompt(), tasks, findings);
          provider = "openai-compatible";
        } catch (Exception ignored) {
          // A completed scan must remain answerable even when the configured model is unavailable.
        }
      }

      Map<String, Long> severityCounts = severityCounts(findings);
      int successCount =
          (int) tasks.stream().filter(task -> "SUCCESS".equals(task.getStatus())).count();
      int failedCount = tasks.size() - successCount;
      auditService.record(
          "AI_ANSWER_TASK_RESULTS",
          "TARGET",
          target.getId(),
          "taskIds="
              + requestedIds
              + "; provider="
              + provider
              + "; prompt="
              + abbreviate(request.prompt(), 500),
          "SUCCESS");
      return new AiAnswerResponse(
          target.getId(),
          requestedIds,
          provider,
          modelClient.model(),
          answer,
          tasks.size(),
          successCount,
          failedCount,
          findings.size(),
          severityCounts);
    } catch (RuntimeException ex) {
      auditService.record(
          "AI_ANSWER_TASK_RESULTS",
          "TARGET",
          request.targetId(),
          "taskIds="
              + request.taskIds()
              + "; prompt="
              + abbreviate(request.prompt(), 500)
              + "; error="
              + abbreviate(ex.getMessage(), 500),
          "FAILED");
      throw ex;
    }
  }

  private List<Long> validateTaskIds(List<Long> taskIds) {
    if (taskIds == null || taskIds.isEmpty()) {
      throw new ApiException("至少需要一个任务结果才能生成回答");
    }
    if (taskIds.size() > MAX_TASKS) {
      throw new ApiException("单次最多汇总 " + MAX_TASKS + " 个任务");
    }
    LinkedHashSet<Long> unique = new LinkedHashSet<>(taskIds);
    if (unique.contains(null) || unique.size() != taskIds.size()) {
      throw new ApiException("任务编号不能为空或重复");
    }
    return List.copyOf(unique);
  }

  private List<SecurityTask> loadAuthorizedTerminalTasks(
      AuthorizedTarget target, Long projectId, List<Long> taskIds) {
    Map<Long, SecurityTask> byId =
        taskRepository.findAllById(taskIds).stream()
            .collect(Collectors.toMap(SecurityTask::getId, Function.identity()));
    if (byId.size() != taskIds.size()
        || taskIds.stream()
            .map(byId::get)
            .anyMatch(task -> task == null || !Objects.equals(task.getTargetId(), target.getId()))) {
      throw new ApiException("任务不存在或不属于当前授权目标");
    }
    List<SecurityTask> tasks = taskIds.stream().map(byId::get).toList();
    for (SecurityTask task : tasks) {
      if (!Objects.equals(task.getProjectId(), projectId)) {
        throw new ApiException("任务不属于当前评估项目");
      }
    }    List<String> unfinished =
        tasks.stream()
            .filter(task -> !TERMINAL_STATUSES.contains(task.getStatus()))
            .map(task -> task.getId() + "(" + task.getStatus() + ")")
            .toList();
    if (!unfinished.isEmpty()) {
      throw new ApiException("任务尚未完成，请等待后再生成回答: " + String.join(", ", unfinished));
    }
    return tasks;
  }

  private String callModel(
      AuthorizedTarget target, String prompt, List<SecurityTask> tasks, List<Finding> findings)
      throws Exception {
    Map<String, Object> context = modelContext(target, tasks, findings);
    String contextJson =
        abbreviate(objectMapper.writeValueAsString(context), MAX_MODEL_CONTEXT_CHARS);
    String system =
        "你是授权安全检测结果分析助手。只能依据提供的任务结果和发现项回答，不得虚构。"
            + "请用简洁中文直接回答用户问题，说明检测是否成功、关键风险、证据局限和优先修复建议；"
            + "任务失败时明确说明未覆盖范围。不要输出攻击步骤、利用代码或未经证据支持的结论。";
    system = ToolboxProgramGuide.context() + "\n" + system;
    return modelClient.complete(system, "用户问题：" + prompt + "\n检测结果(JSON)：" + contextJson);
  }

  private Map<String, Object> modelContext(
      AuthorizedTarget target, List<SecurityTask> tasks, List<Finding> findings) {
    List<Map<String, Object>> taskContext =
        tasks.stream()
            .map(
                task -> {
                  Map<String, Object> item = new LinkedHashMap<>();
                  item.put("taskId", task.getId());
                  item.put("toolCode", task.getToolCode());
                  item.put("status", task.getStatus());
                  item.put("resultJson", abbreviate(task.getResultJson(), 6000));
                  item.put("errorMessage", abbreviate(task.getErrorMessage(), 1000));
                  return item;
                })
            .toList();
    List<Map<String, Object>> findingContext =
        findings.stream()
            .limit(MAX_FINDING_DETAILS)
            .map(
                finding -> {
                  Map<String, Object> item = new LinkedHashMap<>();
                  item.put("taskId", finding.getTaskId());
                  item.put("title", finding.getTitle());
                  item.put("severity", finding.getSeverity());
                  item.put("status", finding.getStatus());
                  item.put("description", abbreviate(finding.getDescription(), 1200));
                  item.put("evidence", abbreviate(finding.getEvidence(), 1200));
                  item.put("remediation", abbreviate(finding.getRemediation(), 1200));
                  return item;
                })
            .toList();
    Map<String, Object> context = new LinkedHashMap<>();
    context.put(
        "target",
        Map.of("id", target.getId(), "name", target.getName(), "value", target.getTargetValue()));
    context.put("tasks", taskContext);
    context.put("findingCount", findings.size());
    context.put("severityCounts", severityCounts(findings));
    context.put("findings", findingContext);
    context.put("findingDetailsTruncated", findings.size() > MAX_FINDING_DETAILS);
    return context;
  }

  private String localAnswer(String prompt, List<SecurityTask> tasks, List<Finding> findings) {
    int successCount =
        (int) tasks.stream().filter(task -> "SUCCESS".equals(task.getStatus())).count();
    List<SecurityTask> failed =
        tasks.stream().filter(task -> !"SUCCESS".equals(task.getStatus())).toList();
    Map<String, Long> counts = severityCounts(findings);
    StringBuilder answer = new StringBuilder();
    String normalizedPrompt = prompt == null ? "" : prompt.toLowerCase(Locale.ROOT);
    if (!findings.isEmpty()
        && containsAny(
            normalizedPrompt, "最严重", "哪个问题", "优先", "先修", "高危", "重点", "怎么修", "如何修复", "怎么办")) {
      Finding highest =
          findings.stream()
              .min(Comparator.comparingInt(finding -> severityRank(finding.getSeverity())))
              .orElse(findings.get(0));
      answer
          .append("最需要优先处理的是 [")
          .append(normalizeSeverity(highest.getSeverity()))
          .append("] ")
          .append(highest.getTitle())
          .append("。");
      if (!isBlank(highest.getRemediation())) {
        answer.append("建议先").append(abbreviate(highest.getRemediation(), 300));
      }
      answer.append("\n\n");
    }
    answer
        .append("检测已完成：共 ")
        .append(tasks.size())
        .append(" 个任务，成功 ")
        .append(successCount)
        .append(" 个，失败或被拒绝 ")
        .append(failed.size())
        .append(" 个。\n\n");

    List<String> summaries = new ArrayList<>();
    for (SecurityTask task : tasks) {
      if ("SUCCESS".equals(task.getStatus())) {
        String summary = resultSummary(task.getResultJson());
        summaries.add("- " + task.getToolCode() + "：" + (summary.isBlank() ? "执行成功" : summary));
      } else {
        summaries.add(
            "- "
                + task.getToolCode()
                + "："
                + task.getStatus()
                + "，"
                + (isBlank(task.getErrorMessage())
                    ? "没有可用的检测结果"
                    : abbreviate(task.getErrorMessage(), 300)));
      }
    }
    answer.append("任务结果：\n").append(String.join("\n", summaries)).append("\n\n");

    if (findings.isEmpty()) {
      answer.append("本次没有生成安全发现项。但这只表示已执行的检查未发现问题，不代表目标不存在其他风险。");
    } else {
      answer
          .append("共发现 ")
          .append(findings.size())
          .append(" 项：")
          .append(
              SEVERITY_ORDER.stream()
                  .filter(counts::containsKey)
                  .map(level -> level + " " + counts.get(level) + " 项")
                  .collect(Collectors.joining("，")))
          .append("。\n");
      findings.stream()
          .sorted(Comparator.comparingInt(finding -> severityRank(finding.getSeverity())))
          .limit(5)
          .forEach(
              finding ->
                  answer
                      .append("- [")
                      .append(normalizeSeverity(finding.getSeverity()))
                      .append("] ")
                      .append(finding.getTitle())
                      .append("\n"));
      List<String> remediations =
          findings.stream()
              .map(Finding::getRemediation)
              .filter(value -> !isBlank(value))
              .map(value -> abbreviate(value, 300))
              .distinct()
              .limit(3)
              .toList();
      if (!remediations.isEmpty()) {
        answer.append("\n优先建议：\n");
        remediations.forEach(value -> answer.append("- ").append(value).append("\n"));
      }
    }
    if (!failed.isEmpty()) {
      answer.append("\n注意：存在未成功执行的任务，对应检查范围不能据此下结论。");
    }
    return answer.toString().strip();
  }

  private boolean containsAny(String text, String... words) {
    return Arrays.stream(words).anyMatch(text::contains);
  }

  private String resultSummary(String resultJson) {
    if (isBlank(resultJson)) {
      return "";
    }
    try {
      return abbreviate(objectMapper.readTree(resultJson).path("summary").asText(""), 500);
    } catch (Exception ignored) {
      return "结果已保存，但摘要格式无法解析";
    }
  }

  private Map<String, Long> severityCounts(List<Finding> findings) {
    Map<String, Long> raw =
        findings.stream()
            .collect(
                Collectors.groupingBy(
                    finding -> normalizeSeverity(finding.getSeverity()), Collectors.counting()));
    Map<String, Long> ordered = new LinkedHashMap<>();
    SEVERITY_ORDER.forEach(
        level -> {
          if (raw.containsKey(level)) {
            ordered.put(level, raw.get(level));
          }
        });
    raw.forEach(ordered::putIfAbsent);
    return Map.copyOf(ordered);
  }

  private int severityRank(String severity) {
    int index = SEVERITY_ORDER.indexOf(normalizeSeverity(severity));
    return index < 0 ? SEVERITY_ORDER.size() : index;
  }

  private String normalizeSeverity(String severity) {
    return isBlank(severity) ? "UNKNOWN" : severity.toUpperCase(Locale.ROOT);
  }

  private String abbreviate(String value, int maxLength) {
    if (value == null) {
      return "";
    }
    return value.length() <= maxLength ? value : value.substring(0, maxLength) + "…";
  }

  private boolean isBlank(String value) {
    return value == null || value.isBlank();
  }
}
