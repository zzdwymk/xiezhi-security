package com.bachelor.toolbox.report;

import com.bachelor.toolbox.ai.AiAnswerRequest;
import com.bachelor.toolbox.ai.AiAnswerResponse;
import com.bachelor.toolbox.ai.AiAnswerService;
import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.finding.Finding;
import com.bachelor.toolbox.finding.FindingRepository;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.AuthorizedTargetRepository;
import com.bachelor.toolbox.task.SecurityTask;
import com.bachelor.toolbox.task.TaskService;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

@Service
public class ReportService {
  private static final Logger log = LoggerFactory.getLogger(ReportService.class);
  private static final ZoneId REPORT_ZONE = ZoneId.of("Asia/Shanghai");
  private static final DateTimeFormatter TIME_FORMATTER =
      DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss z").withZone(REPORT_ZONE);

  private final TaskService taskService;
  private final AuthorizedTargetRepository targetRepository;
  private final FindingRepository findingRepository;
  private final AiAnswerService aiAnswerService;

  public ReportService(
      TaskService taskService,
      AuthorizedTargetRepository targetRepository,
      FindingRepository findingRepository,
      AiAnswerService aiAnswerService) {
    this.taskService = taskService;
    this.targetRepository = targetRepository;
    this.findingRepository = findingRepository;
    this.aiAnswerService = aiAnswerService;
  }

  public String generateTaskReport(Long taskId) {
    SecurityTask task = taskService.get(taskId);
    AuthorizedTarget target = targetRepository.findById(task.getTargetId()).orElse(null);
    List<Finding> findings = findingRepository.findAllByTaskIdOrderByCreatedAtAsc(taskId);
    Instant generatedAt = Instant.now();

    StringBuilder html = new StringBuilder(16_384);
    html.append(
        """
<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>授权安全测试报告</title>
  <style>
    :root { color-scheme: light; font-family: "Microsoft YaHei", "PingFang SC", sans-serif; color: #172033; }
    body { margin: 0; background: #f4f7fb; line-height: 1.65; }
    main { max-width: 980px; margin: 32px auto; padding: 36px 44px; background: #fff; box-shadow: 0 8px 32px rgba(20, 39, 70, .10); }
    h1 { margin: 0 0 6px; font-size: 30px; }
    h2 { margin-top: 32px; padding-bottom: 8px; border-bottom: 2px solid #dce6f3; font-size: 21px; }
    h3 { margin-bottom: 8px; font-size: 17px; }
    .muted { color: #65738a; }
    .notice { padding: 16px 18px; border-left: 5px solid #2563eb; background: #eff6ff; }
    .grid { display: grid; grid-template-columns: 180px 1fr; border: 1px solid #dce3ed; border-bottom: 0; }
    .grid > div { padding: 9px 12px; border-bottom: 1px solid #dce3ed; overflow-wrap: anywhere; }
    .label { background: #f7f9fc; font-weight: 700; }
    .finding { margin: 18px 0; padding: 18px; border: 1px solid #dce3ed; border-radius: 8px; page-break-inside: avoid; }
    .severity { display: inline-block; margin-left: 8px; padding: 2px 9px; border-radius: 999px; background: #eef2f7; font-size: 12px; }
    pre { margin: 8px 0 0; padding: 12px; background: #0f172a; color: #e2e8f0; white-space: pre-wrap; overflow-wrap: anywhere; border-radius: 6px; }
    .empty { padding: 18px; color: #526078; background: #f8fafc; border: 1px dashed #b8c4d4; }
    footer { margin-top: 38px; padding-top: 14px; border-top: 1px solid #dce3ed; color: #65738a; font-size: 13px; }
    @media print { body { background: #fff; } main { margin: 0; max-width: none; box-shadow: none; } }
  </style>
</head>
<body><main>
""");

    html.append("<h1>授权安全测试报告</h1>")
        .append("<div class=\"muted\">任务编号：")
        .append(task.getId())
        .append("</div>")
        .append("<h2>授权声明</h2>")
        .append("<div class=\"notice\"><strong>本报告仅适用于已获得明确授权的安全测试范围。</strong><br>")
        .append(
            text(
                task.getAuthorizationStatementSnapshot() != null
                    ? task.getAuthorizationStatementSnapshot()
                    : target == null ? null : target.getAuthorizationNote()))
        .append("</div>")
        .append("<h2>测试范围</h2><div class=\"grid\">")
        .append(row("授权目标快照", task.getTargetSnapshotJson()))
        .append(row("允许端口快照", task.getAllowedPortsSnapshot()))
        .append(row("授权生效时间", format(task.getAuthorizationValidFromSnapshot())))
        .append(row("授权到期时间", format(task.getAuthorizationExpiresAtSnapshot())))
        .append(row("快照采集时间", format(task.getSnapshotCapturedAt())))
        .append("</div>")
        .append("<h2>任务与工具</h2><div class=\"grid\">")
        .append(row("测试工具", task.getToolCode()))
        .append(row("工具版本快照", task.getToolVersionSnapshot()))
        .append(row("规则版本 SHA-256", task.getRuleVersionSnapshot()))
        .append(row("Nuclei 模板集合 SHA-256", task.getNucleiTemplateHashSnapshot()))
        .append(row("任务状态", task.getStatus()))
        .append(row("执行进度", task.getProgress() + "%"))
        .append(row("创建时间", format(task.getCreatedAt())))
        .append(row("开始时间", format(task.getStartedAt())))
        .append(row("完成时间", format(task.getFinishedAt())))
        .append(row("请求参数", task.getRequestJson()))
        .append(row("执行结果", task.getResultJson()))
        .append(row("错误信息", reportErrorMessage(task)))
        .append("</div>");

    String aiSummary = generateAiSummary(task);
    html.append("<h2>AI 综合研判</h2>")
        .append("<div class=\"notice\">")
        .append(multiline(aiSummary))
        .append("</div>")
        .append("<h2>漏洞与风险发现</h2>");

    if (findings.isEmpty()) {
      html.append("<div class=\"empty\">该任务当前没有生成漏洞记录。此结果不代表目标不存在其他安全风险。</div>");
    } else {
      for (int index = 0; index < findings.size(); index++) {
        Finding finding = findings.get(index);
        html.append("<section class=\"finding\"><h3>")
            .append(index + 1)
            .append(". ")
            .append(text(finding.getTitle()))
            .append("<span class=\"severity\">")
            .append(text(finding.getSeverity()))
            .append("</span></h3>")
            .append("<div><strong>来源工具：</strong>")
            .append(text(finding.getSourceTool()))
            .append("</div>")
            .append("<div><strong>发现时间：</strong>")
            .append(text(format(finding.getCreatedAt())))
            .append("</div>")
            .append("<h3>风险说明</h3><div>")
            .append(multiline(finding.getDescription()))
            .append("</div>")
            .append("<h3>证据</h3><pre>")
            .append(text(valueOrPlaceholder(finding.getEvidence())))
            .append("</pre>")
            .append("<h3>修复建议</h3><div>")
            .append(multiline(finding.getRemediation()))
            .append("</div>")
            .append("</section>");
      }
    }

    html.append("<footer>报告生成时间：")
        .append(text(format(generatedAt)))
        .append("。报告内容基于任务执行时保存的数据自动生成。</footer>")
        .append("</main></body></html>");
    return html.toString();
  }

  private String generateAiSummary(SecurityTask task) {
    try {
      AiAnswerResponse response =
          aiAnswerService.answer(
              new AiAnswerRequest(
                  task.getProjectId(),
                  task.getTargetId(),
                  "请为授权安全测试报告生成综合摘要，说明执行状态、关键风险、证据局限和整改优先级。",
                  List.of(task.getId())));      if (response.answer() != null && !response.answer().isBlank()) {
        return response.answer();
      }
    } catch (RuntimeException exception) {
      log.warn("生成任务报告的 AI 综合研判失败，taskId={}", task.getId(), exception);
    }
    return "AI 综合研判暂不可用。报告仍保留任务执行状态、原始结果和风险发现，供人工复核。";
  }

  private String row(String label, Object value) {
    return "<div class=\"label\">"
        + text(label)
        + "</div><div>"
        + multiline(value == null ? null : value.toString())
        + "</div>";
  }

  private String multiline(String value) {
    return text(valueOrPlaceholder(value))
        .replace("\r\n", "<br>")
        .replace("\n", "<br>")
        .replace("\r", "<br>");
  }

  private String valueOrPlaceholder(String value) {
    return value == null || value.isBlank() ? "未提供" : value;
  }

  private String reportErrorMessage(SecurityTask task) {
    if (task.getErrorMessage() == null || task.getErrorMessage().isBlank()) {
      return null;
    }
    if ("CANCELLED".equals(task.getTerminationReason()) || "CANCELLED".equals(task.getStatus())) {
      return "用户取消任务";
    }
    if ("TIMEOUT".equals(task.getTerminationReason()) || "TIMEOUT".equals(task.getStatus())) {
      return "任务执行超时，请稍后重试";
    }
    if ("AUTHORIZATION_CHANGED".equals(task.getTerminationReason())) {
      return "任务授权状态已变更，请重新确认授权后再试";
    }
    return "任务执行失败，请稍后重试";
  }

  private String format(Instant instant) {
    return instant == null ? "未记录" : TIME_FORMATTER.format(instant);
  }

  private String text(String value) {
    if (value == null) {
      return "";
    }
    return value
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\"", "&quot;")
        .replace("'", "&#39;");
  }
}
