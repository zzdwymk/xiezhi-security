package com.bachelor.toolbox.ai;

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
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;
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

  public AiProjectIndexService(
      AiAgentRuntimeClient runtime,
      AssessmentProjectService projects,
      ProjectTargetRepository projectTargets,
      AuthorizedTargetRepository targets,
      SecurityTaskRepository tasks,
      FindingRepository findings,
      ReconResultRepository recon,
      ProbeResultRepository probes) {
    this.runtime = runtime;
    this.projects = projects;
    this.projectTargets = projectTargets;
    this.targets = targets;
    this.tasks = tasks;
    this.findings = findings;
    this.recon = recon;
    this.probes = probes;
  }

  /** Returns false on any indexing failure; agent planning must continue with direct context. */
  public boolean refreshBestEffort(Long projectId) {
    if (!runtime.enabled()) return false;
    try {
      runtime.indexProject(projectId, collect(projectId));
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
            "项目说明：" + safe(project.getDescription())),
        "project",
        Map.of("projectId", projectId.toString(), "kind", "authorization"));

    List<ProjectTarget> links = projectTargets.findByProjectId(projectId);
    Map<Long, AuthorizedTarget> targetById =
        targets.findAllById(links.stream().map(ProjectTarget::getTargetId).toList()).stream()
            .collect(Collectors.toMap(AuthorizedTarget::getId, Function.identity()));
    links.stream()
        .limit(40)
        .map(link -> targetById.get(link.getTargetId()))
        .filter(Objects::nonNull)
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

    List<SecurityTask> projectTasks =
        tail(tasks.findAllByProjectIdOrderByCreatedAtAsc(projectId), 60);
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
              "进度：" + task.getProgress() + "%",
              "创建时间：" + time(task.getCreatedAt()),
              "结束时间：" + time(task.getFinishedAt()),
              "终止原因：" + safe(task.getTerminationReason()),
              "错误摘要：" + limit(task.getErrorMessage(), 1000),
              "结果摘要：" + limit(task.getResultJson(), 2500)),
          "task",
          Map.of(
              "taskId",
              task.getId().toString(),
              "targetId",
              task.getTargetId().toString(),
              "kind",
              "scan-task"));
    }

    List<Long> indexedTaskIds = projectTasks.stream().map(SecurityTask::getId).toList();
    List<Finding> projectFindings =
        indexedTaskIds.isEmpty()
            ? List.of()
            : tail(findings.findAllByTaskIdInOrderByCreatedAtAsc(indexedTaskIds), 60);
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
