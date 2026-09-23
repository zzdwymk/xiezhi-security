package com.bachelor.toolbox.report;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.finding.Finding;
import com.bachelor.toolbox.finding.FindingClassification;
import com.bachelor.toolbox.finding.FindingRepository;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.TargetService;
import com.bachelor.toolbox.task.SecurityTask;
import com.bachelor.toolbox.task.SecurityTaskRepository;
import com.lowagie.text.Chunk;
import com.lowagie.text.Document;
import com.lowagie.text.DocumentException;
import com.lowagie.text.Element;
import com.lowagie.text.Font;
import com.lowagie.text.PageSize;
import com.lowagie.text.Paragraph;
import com.lowagie.text.Phrase;
import com.lowagie.text.pdf.BaseFont;
import com.lowagie.text.pdf.PdfPCell;
import com.lowagie.text.pdf.PdfPTable;
import com.lowagie.text.pdf.PdfWriter;
import java.awt.Color;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

@Service
public class ProjectReportService {
  private static final Logger log = LoggerFactory.getLogger(ProjectReportService.class);
  private static final DateTimeFormatter TIME_FORMATTER = ReportFormatters.TIME_FORMATTER;
  private static final String FLUENT_INFO_ICON =
      "<svg class=\"notice-icon\" viewBox=\"0 0 20 20\" fill=\"currentColor\" aria-hidden=\"true\"><path fill-rule=\"evenodd\" d=\"M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a.75.75 0 000 1.5h.253a.25.25 0 01.247.25v3.5a.75.75 0 001.5 0v-3.5A1.75 1.75 0 009.253 9H9z\" clip-rule=\"evenodd\"/></svg>";
  private static final List<String> SEVERITY_ORDER =
      List.of("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO");

  private final TargetService targetService;
  private final SecurityTaskRepository taskRepository;
  private final FindingRepository findingRepository;

  public ProjectReportService(
      TargetService targetService,
      SecurityTaskRepository taskRepository,
      FindingRepository findingRepository) {
    this.targetService = targetService;
    this.taskRepository = taskRepository;
    this.findingRepository = findingRepository;
  }

  public String generateHtml(Long targetId) {
    ProjectData data = load(targetId);
    StringBuilder html = new StringBuilder(32_768);
    html.append(
        """
<!doctype html><html lang="zh-CN"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>项目级授权安全测试报告</title><style>
body{margin:0;background:#f4f7fb;color:#172033;font:14px/1.65 "Microsoft YaHei",sans-serif}
main{max-width:1050px;margin:28px auto;padding:38px 44px;background:#fff;box-shadow:0 8px 30px #14274618}
h1{margin:0}h2{margin-top:30px;border-bottom:2px solid #dce6f3;padding-bottom:7px}
table{width:100%;border-collapse:collapse;margin:12px 0}th,td{border:1px solid #dce3ed;padding:8px;text-align:left;vertical-align:top;overflow-wrap:anywhere}
th{background:#f5f8fc}.notice{display:flex;gap:12px;align-items:flex-start;padding:12px 16px;background:#f0f6ff;border:1px solid #c7dcff;border-radius:6px;color:#242424;margin:12px 0;line-height:1.6}.notice-icon{flex-shrink:0;width:18px;height:18px;margin-top:2px;color:#0f6cbd}.notice-body{flex:1;min-width:0}.notice-title{font-weight:600;color:#1a1a1a;margin-bottom:3px}
.cards{display:grid;grid-template-columns:repeat(5,1fr);gap:10px}.card{padding:13px;border:1px solid #dce3ed;border-radius:7px}.num{font-size:24px;font-weight:700}
.finding{page-break-inside:avoid;margin:14px 0;padding:16px 20px;border:1px solid #e1dfdd;border-radius:8px;background:#fff;box-shadow:0 1.6px 3.6px 0 rgba(0,0,0,0.04),0 0.3px 0.9px 0 rgba(0,0,0,0.02)}.finding.finding-critical{border-color:#fecaca;background:#fffcfc}.finding.finding-high{border-color:#fed7aa;background:#fffdfa}.finding.finding-medium{border-color:#fde68a;background:#fffff9}.finding.finding-low{border-color:#bfdbfe;background:#fdfdff}.finding.finding-info{border-color:#e2e8f0;background:#fcfcfc}.severity-badge{display:inline-flex;align-items:center;padding:2px 10px;border-radius:12px;font-size:12px;font-weight:600;line-height:1.4;border:1px solid transparent;margin-left:8px;vertical-align:middle}.severity-badge.severity-critical{color:#b71c1c;background:#fef2f2;border-color:#fecaca}.severity-badge.severity-high{color:#c2410c;background:#fff7ed;border-color:#fed7aa}.severity-badge.severity-medium{color:#b45309;background:#fffbeb;border-color:#fde68a}.severity-badge.severity-low{color:#0f6cbd;background:#eff6ff;border-color:#bfdbfe}.severity-badge.severity-info{color:#475569;background:#f8fafc;border-color:#e2e8f0}.muted{color:#65738a}
@media print{body{background:#fff}main{margin:0;box-shadow:none}.cards{grid-template-columns:repeat(5,1fr)}}
</style>
""" );
    html.append("<style>")
        .append(ReportFormatters.REPORT_FILTER_CSS)
        .append("</style></head><body><main>");
    html.append("<h1>项目级授权安全测试报告</h1><div class=\"muted\">项目以授权目标为边界 · 生成时间：")
        .append(text(format(data.generatedAt)))
        .append("</div>")
        .append("<h2>项目与授权范围</h2><div class=\"notice\">")
        .append(FLUENT_INFO_ICON)
        .append("<div class=\"notice-body\"><div class=\"notice-title\">")
        .append(text(data.target.getName()))
        .append("</div><div>")
        .append(multiline(data.target.getAuthorizationNote()))
        .append("</div></div></div><table>")
        .append(row("授权目标", data.target.getTargetValue()))
        .append(row("目标类型", ReportFormatters.targetTypeLabel(data.target.getTargetType())))
        .append(row("允许端口", data.target.getAllowedPorts()))
        .append(row("授权生效时间", format(data.target.getAuthorizationValidFrom())))
        .append(row("授权到期时间", format(data.target.getAuthorizationExpiresAt())))
        .append(row("当前启用状态", data.target.isEnabled() ? "已启用" : "已停用"))
        .append("</table><h2>执行概览</h2><table>")
        .append(row("任务总数", String.valueOf(data.tasks.size())))
        .append(row("已完成", String.valueOf(countStatus(data.tasks, "SUCCESS"))))
        .append(row("失败", String.valueOf(countStatus(data.tasks, "FAILED"))))
        .append(row("执行中", String.valueOf(countStatus(data.tasks, "RUNNING"))))
        .append(
            row("漏洞发现", String.valueOf(FindingClassification.vulnerabilityCount(data.findings))))
        .append(row("风险点", String.valueOf(FindingClassification.informationalCount(data.findings))))
        .append("</table><div class=\"cards\">");
    data.severityCounts.forEach(
        (severity, count) ->
            html.append("<div class=\"card\"><div>")
                .append(text(ReportFormatters.severityLabel(severity)))
                .append("</div><div class=\"num\">")
                .append(count)
                .append("</div></div>"));
    html.append(
        "</div><h2>任务清单与执行快照</h2><table><thead><tr><th>ID</th><th>工具</th><th>状态</th><th>创建时间</th><th>工具版本</th><th>规则/模板哈希</th></tr></thead><tbody>");
    for (SecurityTask task : data.tasks) {
      html.append("<tr><td>")
          .append(task.getId())
          .append("</td><td>")
          .append(text(task.getToolCode()))
          .append("</td><td>")
          .append(text(ReportFormatters.taskStatusLabel(task.getStatus())))
          .append("</td><td>")
          .append(text(format(task.getCreatedAt())))
          .append("</td><td>")
          .append(text(task.getToolVersionSnapshot()))
          .append("</td><td>")
          .append(text(joinHashes(task)))
          .append("</td></tr>");
    }
    List<Finding> vulnFindings =
        data.findings.stream()
            .filter(FindingClassification::isVulnerability)
            .sorted(ReportFormatters.FINDING_COMPARATOR)
            .toList();
    List<Finding> infoFindings =
        data.findings.stream()
            .filter(f -> !FindingClassification.isVulnerability(f))
            .sorted(ReportFormatters.FINDING_COMPARATOR)
            .toList();
    html.append("</tbody></table><h2>漏洞发现</h2>");
    if (vulnFindings.isEmpty()) {
      html.append("<div class=\"notice\">")
          .append(FLUENT_INFO_ICON)
          .append("<div class=\"notice-body\">当前项目没有漏洞记录；这不等于目标不存在其他安全风险。</div></div>");
    } else {
      html.append("<div data-rf-list>").append(ReportFormatters.REPORT_FILTER_CONTROL);
      for (Finding finding : vulnFindings) appendFinding(html, finding);
      html.append("</div>");
    }
    html.append("<h2>风险点 / 信息项（开放端口等资产暴露面，不计入漏洞）</h2>");
    if (infoFindings.isEmpty()) {
      html.append("<div class=\"notice\">")
          .append(FLUENT_INFO_ICON)
          .append("<div class=\"notice-body\">暂无信息级发现。</div></div>");
    } else {
      for (Finding finding : infoFindings) appendFinding(html, finding);
    }
    return html.append(
            "<h2>报告说明</h2><div class=\"notice\">")
        .append(FLUENT_INFO_ICON)
        .append("<div class=\"notice-body\">报告聚合该授权目标下的历史任务与发现，并保留各任务创建时的工具、规则和模板快照。结果应结合授权有效期与人工复核使用。</div></div>")
        .append(ReportFormatters.REPORT_FILTER_SCRIPT)
        .append("</main></body></html>")
        .toString();
  }

  public byte[] generatePdf(Long targetId) {
    ProjectData data = load(targetId);
    try (ByteArrayOutputStream output = new ByteArrayOutputStream()) {
      Document document = new Document(PageSize.A4, 42, 42, 48, 48);
      PdfWriter.getInstance(document, output);
      document.addTitle("项目级授权安全测试报告 - " + data.target.getName());
      document.addSubject("授权目标 " + data.target.getTargetValue() + " 的聚合安全测试报告");
      document.addCreator("Xiezhi");
      document.open();
      PdfFonts fonts = fonts();
      addTitle(document, "项目级授权安全测试报告", fonts);
      Paragraph subHeader =
          new Paragraph(
              "项目：" + safe(data.target.getName()) + "    生成时间：" + format(data.generatedAt),
              fonts.small);
      subHeader.setSpacingAfter(10);
      document.add(subHeader);
      addHeading(document, "1. 项目与授权范围", fonts);
      addMessageBar(document, fonts, "授权声明", data.target.getAuthorizationNote());
      addKeyValues(
          document,
          fonts,
          Map.of(
              "授权目标", safe(data.target.getTargetValue()),
              "目标类型", ReportFormatters.targetTypeLabel(data.target.getTargetType()),
              "允许端口", safe(data.target.getAllowedPorts()),
              "授权生效时间", format(data.target.getAuthorizationValidFrom()),
              "授权到期时间", format(data.target.getAuthorizationExpiresAt()),
              "当前启用状态", data.target.isEnabled() ? "已启用" : "已停用"));
      addHeading(document, "2. 执行与风险概览", fonts);
      LinkedHashMap<String, String> overview = new LinkedHashMap<>();
      overview.put("任务总数", String.valueOf(data.tasks.size()));
      overview.put(
          "已完成 / 失败 / 执行中",
          countStatus(data.tasks, "SUCCESS")
              + " / "
              + countStatus(data.tasks, "FAILED")
              + " / "
              + countStatus(data.tasks, "RUNNING"));
      overview.put("漏洞发现", String.valueOf(FindingClassification.vulnerabilityCount(data.findings)));
      overview.put("风险点", String.valueOf(FindingClassification.informationalCount(data.findings)));
      data.severityCounts.forEach((key, value) -> overview.put(ReportFormatters.severityLabel(key), String.valueOf(value)));
      addKeyValues(document, fonts, overview);
      addHeading(document, "3. 任务与执行环境快照", fonts);
      PdfPTable taskTable = table(new float[] {0.7f, 1.4f, 1.1f, 1.7f, 2.2f});
      addHeader(taskTable, fonts, "ID", "工具", "状态", "创建时间", "版本 / 规则 / 模板哈希");
      for (SecurityTask task : data.tasks) {
        addCells(
            taskTable,
            fonts,
            String.valueOf(task.getId()),
            safe(task.getToolCode()),
            ReportFormatters.taskStatusLabel(task.getStatus()),
            format(task.getCreatedAt()),
            safe(task.getToolVersionSnapshot()) + "\n" + joinHashes(task));
      }
      document.add(taskTable);
      List<Finding> vulnFindings =
          data.findings.stream()
              .filter(FindingClassification::isVulnerability)
              .sorted(ReportFormatters.FINDING_COMPARATOR)
              .toList();
      List<Finding> infoFindings =
          data.findings.stream()
              .filter(f -> !FindingClassification.isVulnerability(f))
              .sorted(ReportFormatters.FINDING_COMPARATOR)
              .toList();
      addHeading(document, "4. 漏洞发现", fonts);
      if (vulnFindings.isEmpty()) {
        addMessageBar(document, fonts, "提示", "当前项目没有漏洞记录；这不等于目标不存在其他安全风险。");
      } else {
        int index = 1;
        for (Finding finding : vulnFindings)
          index = findingParagraphs(document, fonts, index, finding);
      }
      addHeading(document, "5. 风险点 / 信息项（开放端口等资产暴露面，不计入漏洞）", fonts);
      if (infoFindings.isEmpty()) {
        addMessageBar(document, fonts, "提示", "暂无信息级发现。");
      } else {
        int infoIndex = 1;
        for (Finding finding : infoFindings)
          infoIndex = findingParagraphs(document, fonts, infoIndex, finding);
      }
      addHeading(document, "6. 报告说明", fonts);
      addMessageBar(
          document,
          fonts,
          "说明",
          "本报告仅适用于已获得明确授权的测试范围。报告聚合项目历史数据并保留任务级执行快照，结论仍需人工复核。");
      document.close();
      return output.toByteArray();
    } catch (DocumentException | IOException exception) {
      log.error("生成目标级 PDF 报告失败，targetId={}", targetId, exception);
      throw new ApiException("PDF 报告生成失败，请稍后重试");
    }
  }

  private void appendFinding(StringBuilder html, Finding finding) {
    String sevClass = ReportFormatters.severityClass(finding.getSeverity());
    String sevLabel = ReportFormatters.severityLabel(finding.getSeverity());
    String statusLabel = ReportFormatters.findingStatusLabel(finding.getStatus());
    html.append("<section class=\"finding finding-")
        .append(sevClass)
        .append("\" data-rf-finding")
        .append(ReportFormatters.findingDataAttrs(finding))
        .append("><strong>#")
        .append(finding.getId())
        .append(" ")
        .append(text(finding.getTitle()))
        .append("</strong><span class=\"severity-badge severity-")
        .append(sevClass)
        .append("\">")
        .append(text(sevLabel))
        .append("</span><div style=\"margin-top:6px\">")
        .append("状态：")
        .append(text(statusLabel))
        .append(" · 来源：")
        .append(text(finding.getSourceTool()))
        .append(" · 任务 ID：")
        .append(finding.getTaskId())
        .append("</div><p>")
        .append(multiline(finding.getDescription()))
        .append("</p><strong>修复建议</strong><p>")
        .append(multiline(finding.getRemediation()))
        .append("</p></section>");
  }

  private static Color severityColor(String severity) {
    return ReportFormatters.severityColor(severity);
  }

  private int findingParagraphs(Document document, PdfFonts fonts, int index, Finding finding)
      throws DocumentException {
    PdfPTable card = new PdfPTable(1);
    card.setWidthPercentage(100);
    card.setSpacingBefore(4);
    card.setSpacingAfter(7);
    PdfPCell cell = new PdfPCell();
    cell.setPadding(8);
    cell.setBorderColor(new Color(220, 227, 237));
    cell.setBorderWidth(0.5f);
    cell.setBackgroundColor(new Color(254, 254, 255));

    Font titleFont = new Font(fonts.base, 10.5f, Font.BOLD, severityColor(finding.getSeverity()));
    Paragraph title =
        new Paragraph(
            index + ". " + safe(finding.getTitle()) + "  [" + ReportFormatters.severityLabel(finding.getSeverity()) + "]",
            titleFont);
    title.setSpacingAfter(3);
    cell.addElement(title);

    Paragraph meta =
        new Paragraph(
            "状态："
                + ReportFormatters.findingStatusLabel(finding.getStatus())
                + "  ·  来源："
                + safe(finding.getSourceTool())
                + "  ·  任务 ID："
                + finding.getTaskId(),
            fonts.small);
    meta.setSpacingAfter(4);
    cell.addElement(meta);

    Paragraph desc = new Paragraph("风险说明：" + safe(finding.getDescription()), fonts.normal);
    desc.setSpacingAfter(3);
    cell.addElement(desc);

    Paragraph rem = new Paragraph("修复建议：" + safe(finding.getRemediation()), fonts.normal);
    cell.addElement(rem);

    card.addCell(cell);
    document.add(card);
    return index + 1;
  }

  private ProjectData load(Long targetId) {
    AuthorizedTarget target = targetService.get(targetId);
    List<SecurityTask> tasks = taskRepository.findAllByTargetIdOrderByCreatedAtAsc(targetId);
    List<Finding> findings = findingRepository.findAllByTargetIdOrderByCreatedAtAsc(targetId);
    LinkedHashMap<String, Long> severityCounts = new LinkedHashMap<>();
    SEVERITY_ORDER.forEach(severity -> severityCounts.put(severity, 0L));
    findings.forEach(
        finding ->
            severityCounts.computeIfPresent(
                safe(finding.getSeverity()).toUpperCase(Locale.ROOT), (key, count) -> count + 1));
    return new ProjectData(
        target, List.copyOf(tasks), List.copyOf(findings), severityCounts, Instant.now());
  }

  private PdfFonts fonts() throws DocumentException, IOException {
    BaseFont base = BaseFont.createFont("STSong-Light", "UniGB-UCS2-H", BaseFont.NOT_EMBEDDED);
    return new PdfFonts(
        base,
        new Font(base, 18, Font.BOLD, new Color(17, 94, 163)),
        new Font(base, 12.5f, Font.BOLD, new Color(15, 84, 140)),
        new Font(base, 9.5f, Font.NORMAL, new Color(36, 36, 36)),
        new Font(base, 8.5f, Font.NORMAL, new Color(97, 97, 97)),
        new Font(base, 9, Font.BOLD, new Color(36, 36, 36)));
  }

  private void addTitle(Document document, String value, PdfFonts fonts) throws DocumentException {
    Paragraph paragraph = new Paragraph(value, fonts.title);
    paragraph.setAlignment(Element.ALIGN_CENTER);
    paragraph.setSpacingAfter(10);
    document.add(paragraph);
  }

  private void addHeading(Document document, String value, PdfFonts fonts)
      throws DocumentException {
    Paragraph paragraph = new Paragraph(value, fonts.heading);
    paragraph.setSpacingBefore(12);
    paragraph.setSpacingAfter(6);
    document.add(paragraph);
  }

  private void addMessageBar(Document document, PdfFonts fonts, String title, String content)
      throws DocumentException {
    PdfPTable table = new PdfPTable(1);
    table.setWidthPercentage(100);
    table.setSpacingBefore(3);
    table.setSpacingAfter(8);
    PdfPCell cell = new PdfPCell();
    cell.setBackgroundColor(new Color(240, 246, 255));
    cell.setBorderColor(new Color(199, 220, 255));
    cell.setBorderWidth(0.75f);
    cell.setPadding(8);
    Paragraph p = new Paragraph();
    p.setLeading(14);
    p.add(new Chunk("【" + title + "】\n", fonts.tableHeader));
    p.add(new Chunk(safe(content), fonts.normal));
    cell.addElement(p);
    table.addCell(cell);
    document.add(table);
  }

  private void addKeyValues(Document document, PdfFonts fonts, Map<String, String> values)
      throws DocumentException {
    PdfPTable table = table(new float[] {1.5f, 4.5f});
    values.forEach(
        (key, value) -> {
          addCell(table, fonts, key, true);
          addCell(table, fonts, value, false);
        });
    document.add(table);
  }

  private PdfPTable table(float[] widths) {
    PdfPTable table = new PdfPTable(widths);
    table.setWidthPercentage(100);
    table.setSpacingAfter(7);
    return table;
  }

  private void addHeader(PdfPTable table, PdfFonts fonts, String... values) {
    for (String value : values) {
      addCell(table, fonts, value, true);
    }
  }

  private void addCells(PdfPTable table, PdfFonts fonts, String... values) {
    for (String value : values) {
      addCell(table, fonts, value, false);
    }
  }

  private void addCell(PdfPTable table, PdfFonts fonts, String value, boolean header) {
    PdfPCell cell = new PdfPCell(new Phrase(safe(value), header ? fonts.tableHeader : fonts.normal));
    cell.setPadding(6);
    cell.setBorderColor(new Color(220, 227, 237));
    cell.setBorderWidth(0.5f);
    if (header) {
      cell.setBackgroundColor(new Color(245, 248, 252));
      cell.setHorizontalAlignment(Element.ALIGN_CENTER);
    }
    table.addCell(cell);
  }

  private long countStatus(List<SecurityTask> tasks, String status) {
    return tasks.stream().filter(task -> status.equals(task.getStatus())).count();
  }

  private String joinHashes(SecurityTask task) {
    return "规则: "
        + safe(task.getRuleVersionSnapshot())
        + "\nNuclei: "
        + safe(task.getNucleiTemplateHashSnapshot());
  }

  private String row(String label, String value) {
    return "<tr><th>" + text(label) + "</th><td>" + multiline(value) + "</td></tr>";
  }

  private String multiline(String value) {
    return text(safe(value)).replace("\r\n", "<br>").replace("\n", "<br>").replace("\r", "<br>");
  }

  private String format(Instant value) {
    return value == null ? "未记录" : TIME_FORMATTER.format(value);
  }

  private String safe(String value) {
    return value == null || value.isBlank() ? "未记录" : value;
  }

  private String text(String value) {
    return safe(value)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\"", "&quot;")
        .replace("'", "&#39;");
  }

  private record ProjectData(
      AuthorizedTarget target,
      List<SecurityTask> tasks,
      List<Finding> findings,
      LinkedHashMap<String, Long> severityCounts,
      Instant generatedAt) {}

  private record PdfFonts(
      BaseFont base,
      Font title,
      Font heading,
      Font normal,
      Font small,
      Font tableHeader) {}
}
