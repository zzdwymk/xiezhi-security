package com.bachelor.toolbox.report;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.finding.Finding;
import com.bachelor.toolbox.finding.FindingClassification;
import com.bachelor.toolbox.project.AssessmentProject;
import com.bachelor.toolbox.project.ProjectTarget;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.AuthorizedTargetRepository;
import com.bachelor.toolbox.task.SecurityTask;
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
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * Generates a genuinely project-scoped report. The older ProjectReportService remains available for
 * target-level compatibility; this service aggregates all targets, tasks, findings and approvals
 * through the authoritative summary.
 */
@Service
public class ProjectAggregateReportService {
  private static final Logger log = LoggerFactory.getLogger(ProjectAggregateReportService.class);
  private static final DateTimeFormatter TIME = ReportFormatters.TIME_FORMATTER;
  private static final String FLUENT_INFO_ICON =
      "<svg class=\"notice-icon\" viewBox=\"0 0 20 20\" fill=\"currentColor\" aria-hidden=\"true\"><path fill-rule=\"evenodd\" d=\"M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a.75.75 0 000 1.5h.253a.25.25 0 01.247.25v3.5a.75.75 0 001.5 0v-3.5A1.75 1.75 0 009.253 9H9z\" clip-rule=\"evenodd\"/></svg>";

  private final ProjectReportSummaryService summaries;
  private final AuthorizedTargetRepository targets;

  public ProjectAggregateReportService(
      ProjectReportSummaryService summaries, AuthorizedTargetRepository targets) {
    this.summaries = summaries;
    this.targets = targets;
  }

  public String generateHtml(Long projectId) {
    ProjectReportSummaryService.Summary summary = summaries.load(projectId);
    AssessmentProject project = summary.project();
    StringBuilder html = new StringBuilder(48_000);
    html.append(
            "<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\"><meta"
                + " name=\"viewport\" content=\"width=device-width,initial-scale=1\">")
        .append("<title>安全评估项目报告</title><style>")
        .append(
            "body{margin:0;background:#f4f7fb;color:#172033;font:14px/1.65 Microsoft"
                + " YaHei,sans-serif}main{max-width:1120px;margin:24px auto;padding:34px"
                + " 42px;background:#fff;box-shadow:0 8px 28px #14274618}h1{margin:0 0"
                + " 4px}h2{margin:28px 0 8px;border-bottom:2px solid"
                + " #dce6f3;padding-bottom:6px}.muted{color:#65738a}.notice{display:flex;gap:12px;align-items:flex-start;padding:12px 16px;background:#f0f6ff;border:1px solid #c7dcff;border-radius:6px;color:#242424;margin:12px 0;line-height:1.6}.notice-icon{flex-shrink:0;width:18px;height:18px;margin-top:2px;color:#0f6cbd}.notice-body{flex:1;min-width:0}.notice-title{font-weight:600;color:#1a1a1a;margin-bottom:3px}.cards{display:grid;grid-template-columns:repeat(6,1fr);gap:9px}.card{padding:11px;border:1px"
                + " solid"
                + " #dce3ed;border-radius:7px}.num{font-size:23px;font-weight:700}table{width:100%;border-collapse:collapse;margin:10px"
                + " 0}th,td{border:1px solid"
                + " #dce3ed;padding:7px;text-align:left;vertical-align:top;overflow-wrap:anywhere}th{background:#f5f8fc}.finding{page-break-inside:avoid;margin:14px 0;padding:16px 20px;border:1px solid #e1dfdd;border-radius:8px;background:#fff;box-shadow:0 1.6px 3.6px 0 rgba(0,0,0,0.04),0 0.3px 0.9px 0 rgba(0,0,0,0.02)}.finding.finding-critical{border-color:#fca5a5;background:#fffbfa}.finding.finding-high{border-color:#f2a0a0;background:#fff7f6}.finding.finding-medium{border-color:#fde047;background:#fefdf0}.finding.finding-low{border-color:#93c5fd;background:#f8fbff}.finding.finding-info{border-color:#cbd5e1;background:#fcfcfd}.severity-badge{display:inline-flex;align-items:center;padding:2px 10px;border-radius:12px;font-size:12px;font-weight:600;line-height:1.4;border:1px solid transparent;margin-left:8px;vertical-align:middle}.severity-badge.severity-critical{color:#a4262c;background:#fdf2f2;border-color:#fecaca}.severity-badge.severity-high{color:#c62828;background:#feecec;border-color:#f8c0c0}.severity-badge.severity-medium{color:#986f0b;background:#fefce8;border-color:#fef08a}.severity-badge.severity-low{color:#0f6cbd;background:#eff6ff;border-color:#bfdbfe}.severity-badge.severity-info{color:#475569;background:#f8fafc;border-color:#e2e8f0}@media"
                + " print{body{background:#fff}main{margin:0;box-shadow:none}}</style>")
        .append("<style>")
        .append(ReportFormatters.REPORT_FILTER_CSS)
        .append("</style></head><body><main>")
        .append("<h1>")
        .append(esc(project.getName()))
        .append(" · 安全评估项目报告</h1>")
        .append("<div class=\"muted\">项目 #")
        .append(project.getId())
        .append(" · 生成时间：")
        .append(esc(format(summary.generatedAt())))
        .append("</div>")
        .append("<h2>项目授权范围</h2><div class=\"notice\">")
        .append(FLUENT_INFO_ICON)
        .append("<div class=\"notice-body\"><div class=\"notice-title\">授权声明</div><div>")
        .append(multiline(project.getAuthorizationStatement()))
        .append("</div></div></div><table>")
        .append(row("负责人", project.getOwner()))
        .append(row("项目状态", ReportFormatters.projectStatusLabel(project.getStatus())))
        .append(row("授权生效时间", format(project.getAuthorizationValidFrom())))
        .append(row("授权到期时间", format(project.getAuthorizationExpiresAt())))
        .append("</table><h2>执行概览</h2><div class=\"cards\">")
        .append(card("目标", summary.targets().size()))
        .append(card("任务", summary.vulnerabilityDiscovery().size()))
        .append(card("漏洞发现", summary.vulnerabilityCount()))
        .append(card("风险点", summary.informationalCount()))
        .append(card("已复测", summary.verification().retestedFindings()))
        .append(card("审批", summary.approvals().size()))
        .append("</div>")
        .append(
            "<h2>授权目标</h2><table><thead><tr><th>名称</th><th>地址</th><th>允许端口</th><th>状态</th></tr></thead><tbody>");
    for (AuthorizedTarget target : targetEntities(summary.targets())) {
      html.append("<tr><td>")
          .append(esc(target.getName()))
          .append("</td><td>")
          .append(esc(target.getTargetValue()))
          .append("</td><td>")
          .append(esc(target.getAllowedPorts()))
          .append("</td><td>")
          .append(target.isEnabled() ? "已启用" : "已停用")
          .append("</td></tr>");
    }
    html.append(
        "</tbody></table><h2>任务与执行快照</h2><table><thead><tr><th>ID</th><th>目标</th><th>工具</th><th>状态</th><th>创建时间</th><th>版本/哈希</th></tr></thead><tbody>");
    for (SecurityTask task : summary.vulnerabilityDiscovery()) {
      html.append("<tr><td>")
          .append(task.getId())
          .append("</td><td>")
          .append(task.getTargetId())
          .append("</td><td>")
          .append(esc(task.getToolCode()))
          .append("</td><td>")
          .append(esc(ReportFormatters.taskStatusLabel(task.getStatus())))
          .append("</td><td>")
          .append(esc(format(task.getCreatedAt())))
          .append("</td><td>")
          .append(esc(task.getToolVersionSnapshot()))
          .append("<br>规则：")
          .append(esc(task.getRuleVersionSnapshot()))
          .append("<br>Nuclei：")
          .append(esc(task.getNucleiTemplateHashSnapshot()))
          .append("</td></tr>");
    }
    List<Finding> vulnFindings =
        summary.findings().stream()
            .filter(FindingClassification::isVulnerability)
            .sorted(ReportFormatters.FINDING_COMPARATOR)
            .toList();
    List<Finding> infoFindings =
        summary.findings().stream()
            .filter(f -> !FindingClassification.isVulnerability(f))
            .sorted(ReportFormatters.FINDING_COMPARATOR)
            .toList();
    html.append("</tbody></table><h2>漏洞发现</h2>");
    if (vulnFindings.isEmpty()) {
      html.append("<div class=\"notice\">")
          .append(FLUENT_INFO_ICON)
          .append("<div class=\"notice-body\">当前项目没有已记录的漏洞发现；这不等于目标不存在其他风险。</div></div>");
    } else {
      html.append("<div data-rf-list>")
          .append(ReportFormatters.REPORT_FILTER_CONTROL);
      for (Finding finding : vulnFindings) {
        appendFinding(html, finding);
      }
      html.append("</div>");
    }
    html.append("<h2>风险点 / 信息项（开放端口等资产暴露面，不计入漏洞）</h2>");
    if (infoFindings.isEmpty()) {
      html.append("<div class=\"notice\">")
          .append(FLUENT_INFO_ICON)
          .append("<div class=\"notice-body\">暂无信息级发现。</div></div>");
    }
    for (Finding finding : infoFindings) {
      appendFinding(html, finding);
    }
    html.append("<h2>审批与安全边界</h2><table><tr><th>审批记录</th><td>")
        .append(summary.approvals().size())
        .append("</td></tr><tr><th>安全边界</th><td>")
        .append(esc(summary.controlledPostExploitation().safetyBoundary()))
        .append("</td></tr></table>")
        .append(ReportFormatters.REPORT_FILTER_SCRIPT)
        .append("</main></body></html>");
    return html.toString();
  }

  public byte[] generatePdf(Long projectId) {
    ProjectReportSummaryService.Summary summary = summaries.load(projectId);
    try (ByteArrayOutputStream output = new ByteArrayOutputStream()) {
      Document document = new Document(PageSize.A4, 40, 40, 46, 46);
      PdfWriter.getInstance(document, output);
      document.addTitle("安全评估项目报告 - " + safe(summary.project().getName()));
      document.open();
      Fonts fonts = fonts();
      title(document, safe(summary.project().getName()) + " · 安全评估项目报告", fonts);
      Paragraph subHeader =
          new Paragraph(
              "项目 #" + summary.project().getId() + "    生成时间：" + format(summary.generatedAt()),
              fonts.small);
      subHeader.setSpacingAfter(10);
      document.add(subHeader);
      heading(document, "1. 项目授权范围", fonts);
      messageBar(document, fonts, "授权声明", summary.project().getAuthorizationStatement());
      keyValues(
          document,
          fonts,
          Map.of(
              "负责人",
              safe(summary.project().getOwner()),
              "状态",
              ReportFormatters.projectStatusLabel(summary.project().getStatus()),
              "授权生效",
              format(summary.project().getAuthorizationValidFrom()),
              "授权到期",
              format(summary.project().getAuthorizationExpiresAt())));
      heading(document, "2. 执行概览", fonts);
      keyValues(
          document,
          fonts,
          Map.of(
              "目标",
              String.valueOf(summary.targets().size()),
              "任务",
              String.valueOf(summary.vulnerabilityDiscovery().size()),
              "漏洞发现",
              String.valueOf(summary.vulnerabilityCount()),
              "风险点",
              String.valueOf(summary.informationalCount()),
              "已复测",
              String.valueOf(summary.verification().retestedFindings()),
              "审批",
              String.valueOf(summary.approvals().size())));
      heading(document, "3. 授权目标", fonts);
      PdfPTable targetTable = table(new float[] {1.4f, 2.2f, 1.6f, 0.8f});
      header(targetTable, fonts, "名称", "地址", "允许端口", "状态");
      for (AuthorizedTarget target : targetEntities(summary.targets())) {
        cells(
            targetTable,
            fonts,
            safe(target.getName()),
            safe(target.getTargetValue()),
            safe(target.getAllowedPorts()),
            target.isEnabled() ? "已启用" : "已停用");
      }
      document.add(targetTable);
      heading(document, "4. 任务与快照", fonts);
      PdfPTable taskTable = table(new float[] {0.6f, 0.7f, 1.2f, 1.0f, 1.5f, 2.0f});
      header(taskTable, fonts, "ID", "目标", "工具", "状态", "创建时间", "版本 / 规则 / 模板哈希");
      for (SecurityTask task : summary.vulnerabilityDiscovery()) {
        cells(
            taskTable,
            fonts,
            String.valueOf(task.getId()),
            String.valueOf(task.getTargetId()),
            safe(task.getToolCode()),
            ReportFormatters.taskStatusLabel(task.getStatus()),
            format(task.getCreatedAt()),
            safe(task.getToolVersionSnapshot())
                + "\n规则: "
                + safe(task.getRuleVersionSnapshot())
                + "\nNuclei: "
                + safe(task.getNucleiTemplateHashSnapshot()));
      }
      document.add(taskTable);
      List<Finding> vulnFindings =
          summary.findings().stream()
              .filter(FindingClassification::isVulnerability)
              .sorted(ReportFormatters.FINDING_COMPARATOR)
              .toList();
      List<Finding> infoFindings =
          summary.findings().stream()
              .filter(f -> !FindingClassification.isVulnerability(f))
              .sorted(ReportFormatters.FINDING_COMPARATOR)
              .toList();
      heading(document, "5. 漏洞发现", fonts);
      if (vulnFindings.isEmpty()) {
        messageBar(document, fonts, "提示", "当前项目没有已记录的漏洞发现；这不等于目标不存在其他风险。");
      }
      int index = 1;
      for (Finding finding : vulnFindings) {
        index = findingParagraphs(document, fonts, index, finding);
      }
      heading(document, "6. 风险点 / 信息项（开放端口等资产暴露面，不计入漏洞）", fonts);
      if (infoFindings.isEmpty()) {
        messageBar(document, fonts, "提示", "暂无信息级发现。");
      }
      int infoIndex = 1;
      for (Finding finding : infoFindings) {
        infoIndex = findingParagraphs(document, fonts, infoIndex, finding);
      }
      heading(document, "7. 审批与安全边界", fonts);
      keyValues(
          document,
          fonts,
          Map.of(
              "审批记录",
              String.valueOf(summary.approvals().size()),
              "安全边界",
              safe(summary.controlledPostExploitation().safetyBoundary())));
      document.close();
      return output.toByteArray();
    } catch (DocumentException | IOException ex) {
      log.error("生成项目级 PDF 报告失败，projectId={}", projectId, ex);
      throw new ApiException("项目 PDF 报告生成失败，请稍后重试");
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
        .append(esc(finding.getTitle()))
        .append("</strong><span class=\"severity-badge severity-")
        .append(sevClass)
        .append("\">")
        .append(esc(sevLabel))
        .append("</span><div style=\"margin-top:6px\">")
        .append("状态：")
        .append(esc(statusLabel))
        .append(" · 来源：")
        .append(esc(finding.getSourceTool()))
        .append(" · 目标 ID：")
        .append(finding.getTargetId())
        .append("</div><p>")
        .append(multiline(finding.getDescription()))
        .append("</p><strong>修复建议</strong><p>")
        .append(multiline(finding.getRemediation()))
        .append("</p></section>");
  }

  private static Color severityColor(String severity) {
    return ReportFormatters.severityColor(severity);
  }

  private int findingParagraphs(Document document, Fonts fonts, int index, Finding finding)
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
                + "  ·  目标 ID："
                + finding.getTargetId(),
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

  private List<AuthorizedTarget> targetEntities(List<ProjectTarget> links) {
    List<AuthorizedTarget> result = new ArrayList<>();
    for (ProjectTarget link : links) {
      targets.findById(link.getTargetId()).ifPresent(result::add);
    }
    return result;
  }

  private Fonts fonts() throws DocumentException, IOException {
    BaseFont base = BaseFont.createFont("STSong-Light", "UniGB-UCS2-H", BaseFont.NOT_EMBEDDED);
    return new Fonts(
        base,
        new Font(base, 18, Font.BOLD, new Color(17, 94, 163)),
        new Font(base, 12.5f, Font.BOLD, new Color(15, 84, 140)),
        new Font(base, 9.5f, Font.NORMAL, new Color(36, 36, 36)),
        new Font(base, 8.5f, Font.NORMAL, new Color(97, 97, 97)),
        new Font(base, 9, Font.BOLD, new Color(36, 36, 36)));
  }

  private void title(Document document, String value, Fonts fonts) throws DocumentException {
    Paragraph paragraph = new Paragraph(value, fonts.title);
    paragraph.setAlignment(Element.ALIGN_CENTER);
    paragraph.setSpacingAfter(10);
    document.add(paragraph);
  }

  private void heading(Document document, String value, Fonts fonts) throws DocumentException {
    Paragraph paragraph = new Paragraph(value, fonts.heading);
    paragraph.setSpacingBefore(12);
    paragraph.setSpacingAfter(6);
    document.add(paragraph);
  }

  private void messageBar(Document document, Fonts fonts, String title, String content)
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

  private void keyValues(Document document, Fonts fonts, Map<String, String> values)
      throws DocumentException {
    PdfPTable table = table(new float[] {1.5f, 4.5f});
    values.forEach(
        (key, value) -> {
          cell(table, fonts, key, true);
          cell(table, fonts, value, false);
        });
    document.add(table);
  }

  private PdfPTable table(float[] widths) {
    PdfPTable table = new PdfPTable(widths);
    table.setWidthPercentage(100);
    table.setSpacingAfter(7);
    return table;
  }

  private void header(PdfPTable table, Fonts fonts, String... values) {
    for (String value : values) {
      cell(table, fonts, value, true);
    }
  }

  private void cells(PdfPTable table, Fonts fonts, String... values) {
    for (String value : values) {
      cell(table, fonts, value, false);
    }
  }

  private void cell(PdfPTable table, Fonts fonts, String value, boolean header) {
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

  private String card(String label, long value) {
    return "<div class=\"card\"><div>"
        + esc(label)
        + "</div><div class=\"num\">"
        + value
        + "</div></div>";
  }

  private String row(String label, String value) {
    return "<tr><th>" + esc(label) + "</th><td>" + multiline(value) + "</td></tr>";
  }

  private String multiline(String value) {
    return esc(safe(value)).replace("\r\n", "<br>").replace("\n", "<br>").replace("\r", "<br>");
  }

  private String format(Instant value) {
    return value == null ? "未记录" : TIME.format(value);
  }

  private String safe(String value) {
    return value == null || value.isBlank() ? "未记录" : value;
  }

  private String esc(String value) {
    return safe(value)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\"", "&quot;")
        .replace("'", "&#39;");
  }

  private record Fonts(
      BaseFont base,
      Font title,
      Font heading,
      Font normal,
      Font small,
      Font tableHeader) {}
}
