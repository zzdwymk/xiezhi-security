package com.bachelor.toolbox.ai;

import com.bachelor.toolbox.asset.DiscoveredPathService;
import com.bachelor.toolbox.finding.Finding;
import com.bachelor.toolbox.finding.FindingRepository;
import com.bachelor.toolbox.probe.ProbeResult;
import com.bachelor.toolbox.probe.ProbeResultRepository;
import com.bachelor.toolbox.project.AssessmentProject;
import com.bachelor.toolbox.project.AssessmentProjectService;
import com.bachelor.toolbox.project.ProjectTarget;
import com.bachelor.toolbox.project.ProjectTargetRepository;
import com.bachelor.toolbox.recon.ReconResult;
import com.bachelor.toolbox.recon.ReconResultRepository;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.AuthorizedTargetRepository;
import com.bachelor.toolbox.task.SecurityTask;
import com.bachelor.toolbox.task.SecurityTaskRepository;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Function;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/** Builds a bounded text-only project snapshot for the local LlamaIndex store. */
@Service
public class AiProjectIndexService {
  private static final Logger log = LoggerFactory.getLogger(AiProjectIndexService.class);
  private static final int MAX_DOCUMENTS = 200;
  private static final int MAX_DOCUMENT_CHARS = 12_000;
  private static final int MAX_TOTAL_CHARS = 250_000;
  private static final DateTimeFormatter DISPLAY_TIME =
      DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneId.of("Asia/Shanghai"));

  private final AiAgentRuntimeClient runtime;
  private final AssessmentProjectService projects;
  private final ProjectTargetRepository projectTargets;
  private final AuthorizedTargetRepository targets;
  private final SecurityTaskRepository tasks;
  private final FindingRepository findings;
  private final ReconResultRepository recon;
  private final ProbeResultRepository probes;
  private final DiscoveredPathService discoveredPaths;

  public AiProjectIndexService(
      AiAgentRuntimeClient runtime,
      AssessmentProjectService projects,
      ProjectTargetRepository projectTargets,
      AuthorizedTargetRepository targets,
      SecurityTaskRepository tasks,
      FindingRepository findings,
      ReconResultRepository recon,
      ProbeResultRepository probes,
      DiscoveredPathService discoveredPaths) {
    this.runtime = runtime;
    this.projects = projects;
    this.projectTargets = projectTargets;
    this.targets = targets;
    this.tasks = tasks;
    this.findings = findings;
    this.recon = recon;
    this.probes = probes;
    this.discoveredPaths = discoveredPaths;
  }

  /** Returns false on any indexing failure; agent planning must continue with direct context. */
  public boolean refreshBestEffort(Long projectId) {
    return refreshBestEffort(projectId, null);
  }

  /** Include a server-resolved reference so old records survive the bounded snapshot cutoff. */
  public boolean refreshBestEffort(Long projectId, AiAgentRuntimeClient.IndexDocument reference) {
    if (!runtime.enabled()) return false;
    try {
      List<AiAgentRuntimeClient.IndexDocument> documents = new ArrayList<>(collect(projectId));
      if (reference != null) documents.add(0, reference);
      runtime.indexProject(projectId, documents);
      return true;
    } catch (RuntimeException ex) {
      log.debug("AI project index refresh skipped for project {}: {}", projectId, ex.getMessage());
      return false;
    }
  }

  List<AiAgentRuntimeClient.IndexDocument> collect(Long projectId) {
    AssessmentProject project = projects.get(projectId);
    DocumentCollector output = new DocumentCollector();
    output.add(
        "项目授权与说明",
        String.join(
            "\n",
            "项目名称：" + safe(project.getName()),
            "项目状态：" + safe(project.getStatus()),
            "项目负责人：" + safe(project.getOwner()),
            "授权开始：" + time(project.getAuthorizationValidFrom()),
            "授权结束：" + time(project.getAuthorizationExpiresAt()),
            "授权声明：" + safe(project.getAuthorizationStatement()),
            "项目说明：" + safe(project.getDescription()),
            // 授权声明是自由文本，只是背景资料；可执行范围永远由"登记目标 + 允许端口"决定。
            // 必须显式告知模型，否则模型会把声明里的地址当成权威范围来源
            // （实测曾据此断言"授权目标是另一个地址"而与本轮实际目标冲突）。
            "可执行范围说明：授权声明为人工填写的背景资料，可能滞后或与实际登记不一致；"
                + "本项目唯一可执行的授权范围以「授权目标」文档中的登记地址与允许端口为准，"
                + "声明文本不授予任何额外目标或端口。若两者冲突，以登记目标为准并明确指出该不一致。"),
        "project",
        Map.of("projectId", projectId.toString(), "kind", "authorization"));

    List<ProjectTarget> links = projectTargets.findByProjectId(projectId);
    Map<Long, AuthorizedTarget> targetById =
        targets.findAllById(links.stream().map(ProjectTarget::getTargetId).toList()).stream()
            .collect(Collectors.toMap(AuthorizedTarget::getId, Function.identity()));
    List<AuthorizedTarget> registeredTargets =
        links.stream()
            .map(link -> targetById.get(link.getTargetId()))
            .filter(Objects::nonNull)
            .toList();
    // 声明与登记目标的一致性核查：声明是自由文本，可能残留历史地址（换靶机后忘记更新）。
    // 这里把冲突显式写进索引，让模型据实说明，而不是把过期地址当成权威授权范围。
    List<String> conflict = authorizationStatementConflicts(project, registeredTargets);
    if (!conflict.isEmpty()) {
      output.add(
          "授权声明与登记目标不一致（重要）",
          String.join(
              "\n",
              "以下地址出现在项目授权声明中，但并不是本项目当前登记的授权目标：",
              String.join("、", conflict),
              "登记目标：" 
                  + registeredTargets.stream()
                      .map(t -> safe(t.getTargetValue()))
                      .collect(Collectors.joining("、")),
              "结论：这些地址不在授权范围内，不得对其执行任何检测；"
                  + "可执行范围以登记目标与允许端口为准。回答时应主动指出该不一致。"),
          "project",
          Map.of("projectId", projectId.toString(), "kind", "authorization-conflict"));
    }
    registeredTargets.stream()
        .limit(40)
        .forEach(
            target ->
                output.add(
                    "授权目标：" + safe(target.getName()),
                    String.join(
                        "\n",
                        "目标编号：" + target.getId(),
                        "名称：" + safe(target.getName()),
                        "地址：" + safe(target.getTargetValue()),
                        "类型：" + safe(target.getTargetType()),
                        "允许端口：" + safe(target.getAllowedPorts()),
                        "目标授权说明：" + safe(target.getAuthorizationNote()),
                        "启用状态：" + target.isEnabled()),
                    "target",
                    Map.of("targetId", target.getId().toString(), "kind", "authorized-target")));

    List<SecurityTask> allProjectTasks = tasks.findAllByProjectIdOrderByCreatedAtAsc(projectId);
    List<SecurityTask> projectTasks = tail(allProjectTasks, 60);
    List<Long> allTaskIds = allProjectTasks.stream().map(SecurityTask::getId).toList();
    List<Finding> allProjectFindings = allTaskIds.isEmpty() ? List.of()
        : findings.findAllByTaskIdInOrderByCreatedAtAsc(allTaskIds);
    if (!links.isEmpty() || !allProjectTasks.isEmpty()) {
      // Project-level questions need the whole project's summary even when the UI
      // retains one selected target. Individual evidence remains target-scoped.
      output.add("项目总览与漏洞整改汇总",
          "项目编号：" + projectId + "\n项目名称：" + safe(project.getName())
              + "\n项目目标数：" + links.size() + "\n项目目标："
              + targetById.values().stream().map(t -> "#" + t.getId() + " " + safe(t.getName()) + " " + safe(t.getTargetValue())).sorted().collect(Collectors.joining("；"))
              + "\n检测任务总数：" + allProjectTasks.size() + "\n任务状态统计："
              + allProjectTasks.stream().collect(Collectors.groupingBy(t -> safe(t.getStatus()), java.util.TreeMap::new, Collectors.counting()))
              + "\n发现记录总数（包括配置风险点，不等于可利用漏洞数）：" + allProjectFindings.size()
              + "\n发现等级统计：" + allProjectFindings.stream().collect(Collectors.groupingBy(f -> safe(f.getSeverity()), java.util.TreeMap::new, Collectors.counting()))
              + "\n发现状态统计：" + allProjectFindings.stream().collect(Collectors.groupingBy(f -> safe(f.getStatus()), java.util.TreeMap::new, Collectors.counting()))
              + "\n最近发现摘要（最多15条，非全部明细）：\n"
              + tail(allProjectFindings, 15).stream().map(f -> "#" + f.getId() + " 目标#" + f.getTargetId() + " " + safe(f.getTitle()) + " " + safe(f.getSeverity()) + " " + safe(f.getStatus())).collect(Collectors.joining("\n"))
              + "\n只用于项目级已有资料分析；不授予跨目标执行权限。扫描记录不证明已成功利用。",
          "project", Map.of("projectId", projectId.toString(), "kind", "project-overview"));
    }
    for (SecurityTask task : projectTasks) {
      output.add(
          "检测任务 #" + task.getId(),
          String.join(
              "\n",
              "目标编号：" + task.getTargetId(),
              "工具：" + safe(task.getToolCode()),
              "规则：" + safe(task.getRuleCode()),
              "漏洞编号：" + safe(task.getVulnerabilityCode()),
              "状态：" + safe(task.getStatus()),
              "最近执行事件：" + AiContextService.redact(task.getProgressMessage(), 300),
              "创建时间：" + time(task.getCreatedAt()),
              "结束时间：" + time(task.getFinishedAt()),
              "终止原因：" + safe(task.getTerminationReason()),
              "错误摘要：" + AiContextService.redact(task.getErrorMessage(), 1000),
              "结果摘要：" + AiContextService.redact(task.getResultJson(), 2500),
              "执行日志摘要：" + AiContextService.redact(task.getExecutionLog(), 1500)),
          "task",
          Map.of(
              "taskId",
              task.getId().toString(),
              "targetId",
              task.getTargetId().toString(),
              "kind",
              "scan-task"));
    }

    List<Finding> projectFindings = tail(allProjectFindings, 60);
    for (Finding finding : projectFindings) {
      output.add(
          "漏洞发现：" + safe(finding.getTitle()),
          String.join(
              "\n",
              "发现编号：" + finding.getId(),
              "任务编号：" + finding.getTaskId(),
              "目标编号：" + finding.getTargetId(),
              "严重性：" + safe(finding.getSeverity()),
              "状态：" + safe(finding.getStatus()),
              "来源工具：" + safe(finding.getSourceTool()),
              "漏洞编号：" + safe(finding.getVulnerabilityCode()),
              "描述：" + limit(finding.getDescription(), 2500),
              "证据摘要：" + limit(finding.getEvidence(), 1200),
              "修复建议：" + limit(finding.getRemediation(), 2500)),
          "finding",
          Map.of(
              "findingId",
              finding.getId().toString(),
              "targetId",
              finding.getTargetId().toString(),
              "kind",
              "finding"));
    }

    recon.findByProjectIdOrderByCollectedAtDesc(projectId).stream()
        .limit(15)
        .forEach(
            item ->
                output.add(
                    "信息收集：" + safe(item.getRootDomain()),
                    reconText(item),
                    "recon",
                    Map.of(
                        "reconId",
                        item.getId().toString(),
                        "targetId",
                        item.getTargetId().toString(),
                        "kind",
                        "recon")));
    // 爬虫发现的端点资产：这是「页面源码链接提取 + 疑似可注入参数候选」的真实产出，
    // 必须写入索引，模型才能基于真实发现的端点规划下一步检测（而不是凭空猜测路径）。
    discoveredPaths.listByProject(projectId).stream()
        .limit(10)
        .forEach(
            item ->
                output.add(
                    "已发现端点资产（目标 #" + item.getTargetId() + "）",
                    String.join(
                        "\n",
                        "目标编号：" + item.getTargetId(),
                        "URL：" + safe(item.getUrl()),
                        "路径：" + safe(item.getPath()),
                        "来源：" + safe(item.getSource()),
                        "备注：" + safe(item.getNote()),
                        "发现时间：" + time(item.getDiscoveredAt()),
                        "只用于在授权范围内选择下一步检测目标；不得对本清单之外的地址发起任何请求。"),
                    "asset",
                    Map.of(
                        "targetId",
                        item.getTargetId().toString(),
                        "kind",
                        "discovered-path")));
    // 全部端点的紧凑清单（一条文档聚合，便于模型一次性看到可选拾目标）
    List<com.bachelor.toolbox.asset.DiscoveredPath> allPaths =
        discoveredPaths.listByProject(projectId);
    if (!allPaths.isEmpty()) {
      Map<Long, List<com.bachelor.toolbox.asset.DiscoveredPath>> byTarget =
          allPaths.stream().collect(Collectors.groupingBy(com.bachelor.toolbox.asset.DiscoveredPath::getTargetId));
      for (Map.Entry<Long, List<com.bachelor.toolbox.asset.DiscoveredPath>> entry
          : byTarget.entrySet()) {
        List<String> lines = new ArrayList<>();
        lines.add("目标编号：" + entry.getKey());
        lines.add("以下为信息收集（站点爬取/链接提取/参数候选探测）真实发现的全部端点：");
        entry.getValue().stream()
            .limit(80)
            .forEach(
                path ->
                    lines.add(
                        "- "
                            + safe(path.getPath())
                            + (path.getNote() == null || path.getNote().isBlank()
                                ? ""
                                : "  （" + AiContextService.redact(path.getNote(), 120) + "）")));
        lines.add(
            "共 " + entry.getValue().size() + " 条。选择下一步检测目标时只能从本清单内选择；"
                + "注入验证（sqlmap）只适用于带查询参数且在授权范围内的端点。");
        output.add(
            "目标 #" + entry.getKey() + " 的已发现端点清单",
            String.join("\n", lines),
            "asset",
            Map.of("targetId", entry.getKey().toString(), "kind", "discovered-paths-summary"));
      }
    }
    probes.findByProjectIdOrderByDetectedAtDesc(projectId).stream()
        .limit(15)
        .forEach(
            item ->
                output.add(
                    "指纹探测：" + safe(item.getUrl()),
                    probeText(item),
                    "probe",
                    Map.of(
                        "probeId",
                        item.getId().toString(),
                        "targetId",
                        item.getTargetId().toString(),
                        "kind",
                        "fingerprint")));
    return output.documents();
  }

  private String reconText(ReconResult item) {
    return String.join(
        "\n",
        "目标编号：" + item.getTargetId(),
        "根域名：" + safe(item.getRootDomain()),
        "收集时间：" + time(item.getCollectedAt()),
        "子域名：" + limit(item.getSubdomains(), 1800),
        "DNS：" + limit(item.getDnsRecords(), 1800),
        "IP信息：" + limit(item.getIpInformation(), 1800),
        "注册信息：" + limit(item.getRegistrationInformation(), 1200),
        "HTTP信息：" + limit(item.getHttpInformation(), 1500),
        "TLS信息：" + limit(item.getTlsInformation(), 1500),
        "网络信息：" + limit(item.getNetworkInformation(), 1200),
        "归属信息：" + limit(item.getGeolocationInformation(), 1200));
  }

  private String probeText(ProbeResult item) {
    return String.join(
        "\n",
        "目标编号：" + item.getTargetId(),
        "URL：" + safe(item.getUrl()),
        "探测时间：" + time(item.getDetectedAt()),
        "技术栈：" + safe(item.getTechnologies()),
        "服务器：" + safe(item.getServer()),
        "框架：" + safe(item.getFramework()),
        "WAF：" + safe(item.getWaf()),
        "证据摘要：" + limit(item.getEvidence(), 2500));
  }

  private <T> List<T> tail(List<T> source, int max) {
    if (source == null || source.size() <= max)
      return source == null ? List.of() : List.copyOf(source);
    return List.copyOf(source.subList(source.size() - max, source.size()));
  }

  private String time(Instant value) {
    return value == null ? "无" : DISPLAY_TIME.format(value);
  }

  /** IPv4 字面量（含可选的端口/路径后缀上下文，只取地址部分）。 */
  private static final Pattern IPV4 =
      Pattern.compile("(?<![\\d.])((?:\\d{1,3}\\.){3}\\d{1,3})(?![\\d.])");

  /**
   * 找出「项目授权声明」里提到、但并非本项目当前登记目标的地址。
   *
   * <p>授权声明是人工填写的自由文本，更换靶机后容易忘记同步（实测出现过声明仍写旧靶机、
   * 而实际登记目标已是新地址的情况）。这类不一致若只交给模型自行发现，换模型或换措辞
   * 就可能被静默忽略，因此这里主动检出并写入索引。
   *
   * <p>只做地址级别的粗粒度比对，不解析 CIDR/域名，避免误报；返回结果去重并保持出现顺序。
   */
  private List<String> authorizationStatementConflicts(
      AssessmentProject project, List<AuthorizedTarget> registeredTargets) {
    String statement = project == null ? null : project.getAuthorizationStatement();
    if (statement == null || statement.isBlank() || registeredTargets.isEmpty()) return List.of();
    Set<String> registered =
        registeredTargets.stream()
            .map(AuthorizedTarget::getTargetValue)
            .filter(Objects::nonNull)
            .flatMap(value -> IPV4.matcher(value).results().map(match -> match.group(1)))
            .collect(Collectors.toCollection(LinkedHashSet::new));
    LinkedHashSet<String> conflicts = new LinkedHashSet<>();
    IPV4.matcher(statement)
        .results()
        .map(match -> match.group(1))
        .filter(address -> !registered.contains(address))
        .forEach(conflicts::add);
    return List.copyOf(conflicts);
  }

  private String safe(String value) {
    return value == null ? "" : value;
  }

  private String limit(String value, int max) {
    String clean = safe(value).replaceAll("[\\p{Cc}&&[^\\r\\n\\t]]", "").strip();
    return clean.length() <= max ? clean : clean.substring(0, max);
  }

  private static final class DocumentCollector {
    private final List<AiAgentRuntimeClient.IndexDocument> documents = new ArrayList<>();
    private int totalChars;

    private void add(String title, String text, String source, Map<String, String> metadata) {
      if (documents.size() >= MAX_DOCUMENTS || totalChars >= MAX_TOTAL_CHARS) return;
      String safeTitle = title == null || title.isBlank() ? "项目资料" : title;
      String safeText = text == null ? "" : text.replaceAll("[\\p{Cc}&&[^\\r\\n\\t]]", "").strip();
      if (safeText.isBlank()) return;
      int allowed = Math.min(MAX_DOCUMENT_CHARS, MAX_TOTAL_CHARS - totalChars);
      if (safeText.length() > allowed) safeText = safeText.substring(0, allowed);
      documents.add(
          new AiAgentRuntimeClient.IndexDocument(
              safeTitle,
              safeText,
              source == null ? "project" : source,
              metadata == null ? Map.of() : new LinkedHashMap<>(metadata)));
      totalChars += safeText.length();
    }

    private List<AiAgentRuntimeClient.IndexDocument> documents() {
      return List.copyOf(documents);
    }
  }
}
