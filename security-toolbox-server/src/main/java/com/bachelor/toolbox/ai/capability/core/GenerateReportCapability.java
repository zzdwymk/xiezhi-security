package com.bachelor.toolbox.ai.capability.core;

import com.bachelor.toolbox.ai.capability.CapabilityKind;
import com.bachelor.toolbox.ai.capability.RiskLevel;
import com.bachelor.toolbox.report.ProjectReportService;
import com.bachelor.toolbox.report.ReportService;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Component;

/**
 * {@code generate_report} —— 生成安全评估报告（设计文档 §4.2 路线 A）。
 *
 * <p>封装 {@code GET /api/reports/projects/{projectId}.html} 与 {@code /api/reports/tasks/{taskId}.html}
 * （{@link ProjectReportService} / {@link ReportService}）。
 *
 * <h2>目标绑定：{@link BindingMode#RESOLVED}</h2>
 *
 * <p>生成报告是<strong>只读聚合</strong>，但它确实"触及目标"：报告内容是该目标的完整漏洞与检测结论汇编，会把目标上
 * 全部发现（含证据、请求响应片段）汇总成一份可外带产物。把它当成"不触及目标"的纯读操作，等于让 Agent 无需任何授权校验
 * 就能把任意目标的完整评估结果导出——这是数据外泄而非扫描越权，但同样落在 §6.0 的 T1"目标越权"里。
 *
 * <p>因此 {@code targetId} 必填并进入 L-A 校验。<strong>不</strong>支持"只给 projectId 就导出整个项目"的写法：
 * 项目级导出会聚合多个目标，护栏无法对"项目"做授权校验（授权单位是目标，不是项目），因此这里显式要求逐个目标生成。
 *
 * <p>等级 {@link RiskLevel#SAFE}、不需确认：报告生成不改状态、不发包，属 §6.6 的 {@code NONE}/{@code BATCH} 档。
 * 这里选 {@code SAFE} 是因为"读"确实是它的主要语义，风险来自数据暴露而非副作用，而授权校验已经由 L-A 承担。
 */
@Component
public class GenerateReportCapability extends AbstractCoreCapability {

  /** 能力码。 */
  public static final String CODE = "generate_report";

  /** 支持的输出格式。 */
  public static final List<String> FORMATS = List.of("HTML", "PDF");

  private final ProjectReportService projectReports;
  private final ReportService taskReports;

  public GenerateReportCapability(ProjectReportService projectReports, ReportService taskReports) {
    super(
        CODE,
        "生成安全报告",
        "为指定授权目标生成安全评估报告，汇总该目标上的任务、漏洞发现、证据与处置状态。"
            + "参数：targetId（授权目标 ID，必填）、format（HTML 或 PDF，默认 HTML）、"
            + "taskId（可选，只生成该任务的报告）。"
            + "报告是目标的完整评估结论汇编，属数据外带，因此需要对目标做授权校验。"
            + "本能力只按单个目标生成，不支持项目级聚合导出。",
        CapabilityKind.READ,
        RiskLevel.SAFE,
        false,
        BindingMode.RESOLVED,
        AiCapabilityLayer.L1);
    this.projectReports = projectReports;
    this.taskReports = taskReports;
  }

  @Override
  public Map<String, Object> parameterSchema() {
    Map<String, Object> properties = new LinkedHashMap<>();
    properties.put("targetId", integerProperty(1, "要生成报告的授权目标 ID，用于护栏 L-A 授权校验"));
    properties.put("format", enumProperty(FORMATS, "输出格式，默认 HTML"));
    properties.put("taskId", integerProperty(1, "可选：只生成该任务的报告，而不是目标全量报告"));
    return objectSchema(properties, List.of("targetId"));
  }

  @Override
  protected void validateCoreParams(Map<String, Object> params) {
    requirePositiveLong(params, "targetId");
    String format = optionalText(params, "format");
    if (format != null && !FORMATS.contains(format.toUpperCase(java.util.Locale.ROOT))) {
      throw new com.bachelor.toolbox.common.ApiException("报告格式仅支持 " + String.join("、", FORMATS));
    }
    optionalPositiveLong(params, "taskId");
  }

  /**
   * 生成报告。
   *
   * @return 报告内容与元信息（{@code format} / {@code bytes} / {@code content}）。PDF 以 Base64 返回，避免把二进制
   *     塞进 JSON 字符串
   */
  public Map<String, Object> generate(Long targetId, String format, Long taskId) {
    String normalized = format == null ? "HTML" : format.trim().toUpperCase(java.util.Locale.ROOT);
    Map<String, Object> result = new LinkedHashMap<>();
    result.put("targetId", targetId);
    result.put("format", normalized);
    if (taskId != null) {
      String html = taskReports.generateTaskReport(taskId);
      if ("PDF".equals(normalized)) {
        throw new com.bachelor.toolbox.common.ApiException("单任务报告暂只支持 HTML 格式");
      }
      result.put("taskId", taskId);
      result.put("content", html);
      result.put("bytes", html.getBytes(StandardCharsets.UTF_8).length);
      return Map.copyOf(result);
    }
    if ("PDF".equals(normalized)) {
      byte[] pdf = projectReports.generatePdf(targetId);
      result.put("contentBase64", java.util.Base64.getEncoder().encodeToString(pdf));
      result.put("bytes", pdf.length);
      return Map.copyOf(result);
    }
    String html = projectReports.generateHtml(targetId);
    result.put("content", html);
    result.put("bytes", html.getBytes(StandardCharsets.UTF_8).length);
    return Map.copyOf(result);
  }
}
