package com.bachelor.toolbox.report;

import com.bachelor.toolbox.finding.Finding;
import java.awt.Color;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;

/**
 * 报告公共格式化与本地化工具。
 * 统一处理时间直观展示、危害等级色彩标识、中文翻译与严重度降序排序。
 */
final class ReportFormatters {
  private ReportFormatters() {}

  public static final ZoneId ZONE = ZoneId.of("Asia/Shanghai");
  public static final DateTimeFormatter TIME_FORMATTER =
      DateTimeFormatter.ofPattern("yyyy年MM月dd日 HH:mm:ss").withZone(ZONE);

  public static final List<String> SEVERITY_ORDER =
      List.of("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO");

  public static int severityRank(String severity) {
    if (severity == null || severity.isBlank()) return SEVERITY_ORDER.size();
    int idx = SEVERITY_ORDER.indexOf(severity.trim().toUpperCase(Locale.ROOT));
    return idx < 0 ? SEVERITY_ORDER.size() : idx;
  }

  /**
   * 严格按照危害等级由高到低（严重 -> 高危 -> 中危 -> 低危 -> 信息）排序，
   * 等级相同时按创建时间降序（最新优先），时间相同时按 ID 升序。
   */
  public static final Comparator<Finding> FINDING_COMPARATOR =
      Comparator.comparingInt((Finding f) -> severityRank(f.getSeverity()))
          .thenComparing(Finding::getCreatedAt, Comparator.nullsLast(Comparator.reverseOrder()))
          .thenComparing(Finding::getId, Comparator.nullsLast(Comparator.naturalOrder()));

  public static String formatTime(Instant instant) {
    return instant == null ? "未记录" : TIME_FORMATTER.format(instant);
  }

  public static String severityLabel(String severity) {
    if (severity == null || severity.isBlank()) return "未知";
    return switch (severity.toUpperCase(Locale.ROOT)) {
      case "CRITICAL" -> "严重 (CRITICAL)";
      case "HIGH" -> "高危 (HIGH)";
      case "MEDIUM" -> "中危 (MEDIUM)";
      case "LOW" -> "低危 (LOW)";
      case "INFO" -> "信息 (INFO)";
      default -> severity;
    };
  }

  public static String severityClass(String severity) {
    if (severity == null || severity.isBlank()) return "info";
    return severity.trim().toLowerCase(Locale.ROOT);
  }

  public static Color severityColor(String severity) {
    if (severity == null) return new Color(97, 97, 97);
    return switch (severity.toUpperCase(Locale.ROOT)) {
      case "CRITICAL" -> new Color(196, 43, 28);
      case "HIGH" -> new Color(188, 75, 0);
      case "MEDIUM" -> new Color(157, 93, 0);
      case "LOW" -> new Color(15, 108, 189);
      default -> new Color(97, 97, 97);
    };
  }

  public static String projectStatusLabel(String status) {
    if (status == null || status.isBlank()) return "未记录";
    return switch (status.toUpperCase(Locale.ROOT)) {
      case "ACTIVE" -> "进行中 (ACTIVE)";
      case "DRAFT" -> "草稿 (DRAFT)";
      case "PAUSED" -> "已暂停 (PAUSED)";
      case "COMPLETED" -> "已完成 (COMPLETED)";
      case "ARCHIVED" -> "已归档 (ARCHIVED)";
      default -> status;
    };
  }

  public static String taskStatusLabel(String status) {
    if (status == null || status.isBlank()) return "未记录";
    return switch (status.toUpperCase(Locale.ROOT)) {
      case "SUCCESS" -> "执行成功 (SUCCESS)";
      case "FAILED" -> "执行失败 (FAILED)";
      case "RUNNING" -> "执行中 (RUNNING)";
      case "PENDING" -> "排队中 (PENDING)";
      case "CANCELED" -> "已取消 (CANCELED)";
      default -> status;
    };
  }

  public static String findingStatusLabel(String status) {
    if (status == null || status.isBlank()) return "未记录";
    return switch (status.toUpperCase(Locale.ROOT)) {
      case "OPEN" -> "待处理 (OPEN)";
      case "VERIFIED" -> "已确认 (VERIFIED)";
      case "RETESTED" -> "已复测 (RETESTED)";
      case "CLOSED" -> "已关闭 (CLOSED)";
      case "FALSE_POSITIVE" -> "误报 (FALSE_POSITIVE)";
      default -> status;
    };
  }

  public static String targetTypeLabel(String type) {
    if (type == null || type.isBlank()) return "未记录";
    return switch (type.toLowerCase(Locale.ROOT)) {
      case "ip" -> "IP 地址";
      case "domain" -> "域名";
      case "url" -> "Web 目标 (URL)";
      case "cidr" -> "网段 (CIDR)";
      default -> type;
    };
  }

  /** HTML 属性转义，用于写入 data-* 属性值，避免标题中的引号/尖括号破坏标签结构。 */
  public static String escAttr(String value) {
    if (value == null) return "";
    return value.replace("&", "&amp;")
        .replace("\"", "&quot;")
        .replace("<", "&lt;")
        .replace(">", "&gt;");
  }

  /**
   * 为漏洞卡片生成供前端筛选/排序解析的结构化 data-* 属性。
   * 导出的 HTML 内嵌脚本与前端预览沙箱外的控制栏均依赖这些属性。
   */
  public static String findingDataAttrs(Finding f) {
    return " data-severity=\""
        + escAttr(f.getSeverity() == null ? "" : f.getSeverity().toUpperCase(Locale.ROOT))
        + "\" data-status=\""
        + escAttr(f.getStatus() == null ? "" : f.getStatus().toUpperCase(Locale.ROOT))
        + "\" data-target=\""
        + f.getTargetId()
        + "\" data-time=\""
        + escAttr(f.getCreatedAt() == null ? "" : TIME_FORMATTER.format(f.getCreatedAt()))
        + "\" data-id=\""
        + f.getId()
        + "\" data-title=\""
        + escAttr(f.getTitle() == null ? "" : f.getTitle())
        + "\"";
  }

  /** 导出报告内嵌筛选控件的样式，追加到各报告 <style> 尾部。 */
  public static final String REPORT_FILTER_CSS =
      ".rf-control{display:flex;flex-wrap:wrap;gap:8px;align-items:center;padding:12px 14px;background:#f0f6ff;border:1px solid #c7dcff;border-radius:6px;margin:14px 0}.rf-control .rf-title{font-weight:600;color:#172033;margin-right:2px}.rf-control input,.rf-control select{padding:6px 10px;border:1px solid #b7cbe4;border-radius:6px;font:inherit;color:#172033;background:#fff}.rf-control input{flex:1 1 180px;min-width:140px}.rf-control button{padding:6px 14px;border:1px solid #6d98c8;border-radius:6px;background:#fff;color:#0f6cbd;cursor:pointer}.rf-control button:hover{background:#e6f0fb}.rf-control .rf-count{margin-left:auto;color:#65738a;font-size:12px}";

  /**
   * 筛选/搜索/排序的控制条 HTML（放置在漏洞列表之前）。真正的执行脚本 {@link #REPORT_FILTER_SCRIPT}
   * 需要等到漏洞卡片都渲染完成后放在报告末尾再注入。
   */
  public static final String REPORT_FILTER_CONTROL =
      "<div class=\"rf-control\"><span class=\"rf-title\">交互筛选与排序</span>"
          + "<input id=\"rf-search\" type=\"search\" placeholder=\"搜索标题 / 来源 / 规则…\" autocomplete=\"off\" />"
          + "<select id=\"rf-severity\" title=\"按危害等级筛选\"><option value=\"\">全部等级</option>"
          + "<option value=\"CRITICAL\">严重</option><option value=\"HIGH\">高危</option>"
          + "<option value=\"MEDIUM\">中危</option><option value=\"LOW\">低危</option><option value=\"INFO\">信息</option></select>"
          + "<select id=\"rf-status\" title=\"按处置状态筛选\"><option value=\"\">全部状态</option>"
          + "<option value=\"OPEN\">待处理</option><option value=\"VERIFIED\">已确认</option>"
          + "<option value=\"RETESTED\">已复测</option><option value=\"CLOSED\">已关闭</option><option value=\"FALSE_POSITIVE\">误报</option></select>"
          + "<select id=\"rf-sort\" title=\"排序方式\"><option value=\"sev-desc\">严重度从高到低</option>"
          + "<option value=\"sev-asc\">严重度从低到高</option><option value=\"time-desc\">时间从新到旧</option>"
          + "<option value=\"time-asc\">时间从旧到新</option><option value=\"id-desc\">ID 从大到小</option><option value=\"id-asc\">ID 从小到大</option></select>"
          + "<button id=\"rf-reset\" type=\"button\" title=\"清除全部筛选\">重置</button>"
          + "<span id=\"rf-count\" class=\"rf-count\"></span></div>";

  /**
   * 内嵌到导出 HTML 报告尾部的只读增强脚本：搜索、危害等级筛选、状态筛选与排序。
   * 脚本自身不依赖任何外部资源，仅在浏览器打开导出的报告时生效；
   * 前端沙箱预览会把 &lt;script&gt; 一并剥离，因此两者互不冲突。
   *
   * <p>工作原理：扫描文档中带 data-rf-finding 的漏洞卡片，依据其 data-* 属性进行搜索/筛选/排序。
   */
  public static final String REPORT_FILTER_SCRIPT =
      "<script>"
          + "(function(){\n"
          + "function $(id){return document.getElementById(id);}\n"
          + "var root=document.querySelector('[data-rf-list]');\n"
          + "var items=root?Array.prototype.slice.call(root.querySelectorAll('[data-rf-finding]')):[];\n"
          + "function rank(s){var o=['CRITICAL','HIGH','MEDIUM','LOW','INFO'];var i=o.indexOf((s||'').toUpperCase());return i<0?o.length:i;}\n"
          + "function apply(){\n"
          + "  var q=($('rf-search').value||'').trim().toLowerCase();\n"
          + "  var sev=$('rf-severity').value;\n"
          + "  var st=$('rf-status').value;\n"
          + "  var sort=$('rf-sort').value;\n"
          + "  var shown=[],hidden=0;\n"
          + "  items.forEach(function(it){\n"
          + "    var ok=1;\n"
          + "    if(sev&&it.getAttribute('data-severity')!==sev)ok=0;\n"
          + "    if(st&&it.getAttribute('data-status')!==st)ok=0;\n"
          + "    if(q){var h=(it.textContent||'').toLowerCase();if(h.indexOf(q)<0)ok=0;}\n"
          + "    if(ok)shown.push(it);else{it.style.display='none';hidden++;}\n"
          + "  });\n"
          + "  var cmp;\n"
          + "  if(sort==='sev-desc')cmp=function(a,b){return rank(a.getAttribute('data-severity'))-rank(b.getAttribute('data-severity'));};\n"
          + "  else if(sort==='sev-asc')cmp=function(a,b){return rank(b.getAttribute('data-severity'))-rank(a.getAttribute('data-severity'));};\n"
          + "  else if(sort==='time-desc')cmp=function(a,b){return (b.getAttribute('data-time')||'').localeCompare(a.getAttribute('data-time')||'');};\n"
          + "  else if(sort==='time-asc')cmp=function(a,b){return (a.getAttribute('data-time')||'').localeCompare(b.getAttribute('data-time')||'');};\n"
          + "  else if(sort==='id-desc')cmp=function(a,b){return (~~b.getAttribute('data-id'))-(~~a.getAttribute('data-id'));};\n"
          + "  else cmp=function(a,b){return (~~a.getAttribute('data-id'))-(~~b.getAttribute('data-id'));};\n"
          + "  shown.sort(cmp);\n"
          + "  if(root){shown.forEach(function(it){root.appendChild(it);it.style.display='';});}\n"
          + "  $('rf-count').textContent = shown.length+' / '+items.length+' 项';\n"
          + "}\n"
          + "if(items.length){\n"
          + "  ['rf-search','rf-severity','rf-status','rf-sort'].forEach(function(id){$(id).addEventListener('input',apply);});\n"
          + "  ['rf-severity','rf-status','rf-sort'].forEach(function(id){$(id).addEventListener('change',apply);});\n"
          + "  $('rf-reset').addEventListener('click',function(){\n"
          + "    $('rf-search').value='';$('rf-severity').value='';$('rf-status').value='';$('rf-sort').value='sev-desc';\n"
          + "    apply();\n"
          + "  });\n"
          + "  apply();\n"
          + "}\n"
          + "})();\n"
          + "</script>";
}
