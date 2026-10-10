package com.bachelor.toolbox.report;

import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import org.commonmark.Extension;
import org.commonmark.ext.gfm.strikethrough.StrikethroughExtension;
import org.commonmark.ext.gfm.tables.TablesExtension;
import org.commonmark.parser.Parser;
import org.commonmark.renderer.html.HtmlRenderer;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.nodes.Node;
import org.jsoup.nodes.TextNode;
import org.jsoup.safety.Cleaner;
import org.jsoup.safety.Safelist;

/** Safe, self-contained Markdown for downloaded reports, matching the chat link/media policy. */
final class ReportMarkdown {
  private static final List<Extension> EXTENSIONS =
      List.of(TablesExtension.create(), StrikethroughExtension.create());
  private static final Parser PARSER = Parser.builder().extensions(EXTENSIONS).build();
  private static final HtmlRenderer RENDERER =
      HtmlRenderer.builder().extensions(EXTENSIONS).softbreak("<br>\n").build();
  private static final Safelist ALLOWED_HTML =
      new Safelist()
          .addTags("p", "br", "h1", "h2", "h3", "h4", "h5", "h6", "ul", "ol", "li",
              "blockquote", "pre", "code", "kbd", "samp", "strong", "em", "del", "s", "hr", "table",
              "thead", "tbody", "tr", "th", "td", "a")
          .addAttributes("a", "href", "title")
          .addAttributes("ol", "start")
          .addProtocols("a", "href", "http", "https", "#")
          .preserveRelativeLinks(true);
  // Display aliases only: the underlying report evidence and model response remain unchanged.
  private static final Map<String, String> INTERNAL_VALUES = Map.ofEntries(
      Map.entry("retrieve_project_context", "项目上下文检索"),
      Map.entry("tcp_ports", "TCP 端口探测"),
      Map.entry("nmap_service_scan", "Nmap 服务识别"),
      Map.entry("http_headers", "HTTP 安全响应头检查"),
      Map.entry("http_security_check", "HTTP 常见安全检查"),
      Map.entry("tls_config", "TLS 基础配置检查"),
      Map.entry("nuclei_scan", "Nuclei 通用漏洞扫描"),
      Map.entry("afrog_scan", "Afrog 漏洞扫描"),
      Map.entry("xray_scan", "Xray 漏洞扫描"),
      Map.entry("zap_scan", "OWASP ZAP 主动扫描"),
      Map.entry("zap_fuzz", "ZAP 单次参数变异验证"),
      Map.entry("sqlmap_scan", "sqlmap SQL 注入检测"),
      Map.entry("fscan_scan", "fscan 主机扫描"),
      Map.entry("msf_scan", "Metasploit 模块执行"),
      Map.entry("PENDING", "待处理"), Map.entry("QUEUED", "排队中"),
      Map.entry("RUNNING", "执行中"), Map.entry("SUCCESS", "已完成"),
      Map.entry("FAILED", "失败"), Map.entry("TIMEOUT", "超时"),
      Map.entry("CANCELLED", "已取消"), Map.entry("APPROVED", "已通过"),
      Map.entry("REJECTED", "已拒绝"), Map.entry("CONFIRMED", "已确认"),
      Map.entry("NOT_REQUIRED", "无需确认"), Map.entry("COMPLETED", "已完成"),
      Map.entry("SKIPPED", "已跳过"), Map.entry("STOPPED", "已停止"),
      Map.entry("BLOCKED", "受阻"), Map.entry("DRAFT", "草稿"),
      Map.entry("DISPATCHED", "已下发"), Map.entry("EXPIRED", "已过期"),
      Map.entry("OPEN", "待确认"), Map.entry("FALSE_POSITIVE", "误报"),
      Map.entry("FIXED", "已修复"), Map.entry("REOPENED", "已复现"),
      Map.entry("WAITING_TASKS", "等待前置任务"));
  private static final String IDENTIFIER_CHARACTER = "[A-Za-z0-9_./:@?=&%#$\\\\-]";
  private static final Pattern INTERNAL_EVIDENCE_ID = Pattern.compile("ev-[0-9a-f]{24}");
  private static final Pattern INTERNAL_EVIDENCE_REFERENCE = Pattern.compile(
      "(?<!" + IDENTIFIER_CHARACTER + ")(?:证据\\s*)?ev-[0-9a-f]{24}(?!" + IDENTIFIER_CHARACTER + ")");
  private static final Pattern INTERNAL_VALUE_PATTERN = Pattern.compile(
      "(?<!" + IDENTIFIER_CHARACTER + ")(?:"
          + INTERNAL_VALUES.keySet().stream().sorted().map(Pattern::quote)
              .collect(Collectors.joining("|"))
          + ")(?!" + IDENTIFIER_CHARACTER + ")");
  private static final Pattern URL_PATTERN = Pattern.compile(
      "(?i)(?:[a-z][a-z0-9+.-]*://|mailto:|www\\.)[^\\s<>\\\"'，。；！？]+"
          + "|[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}");
  private static final Map<String, String> INTERNAL_TERMS = Map.of(
      "AI Runtime", "智能服务", "Harness", "执行校验", "Ledger", "执行记录", "Turn", "对话轮次");
  private static final Pattern INTERNAL_TERM_PATTERN = Pattern.compile(
      "(?<!" + IDENTIFIER_CHARACTER + ")(?:AI Runtime(?!" + IDENTIFIER_CHARACTER + ")"
          + "|Harness(?=\\s*(?:协议|校验|拒绝|中间状态|验证|执行|状态|安全))"
          + "|Ledger(?=\\s*(?:摘要链|证据链|批次|序列|链|事件|记录|状态|持久化|事务|校验))"
          + "|Turn(?=\\s*(?:ID\\b|标识|轮次|状态|请求|上下文|续接|恢复)))");

  private ReportMarkdown() {}

  static String render(String markdown) {
    String rawHtml = RENDERER.render(PARSER.parse(markdown == null ? "" : markdown));
    Document clean = new Cleaner(ALLOWED_HTML).clean(Jsoup.parseBodyFragment(rawHtml));
    clean.outputSettings().prettyPrint(false);
    for (Element anchor : clean.select("a")) {
      if (anchor.hasAttr("title")) anchor.attr("title", localizeText(anchor.attr("title")));
      String href = anchor.attr("href");
      String lowerHref = href.toLowerCase(Locale.ROOT);
      if (lowerHref.startsWith("https://") || lowerHref.startsWith("http://")) {
        anchor.attr("target", "_blank").attr("rel", "noopener noreferrer");
      } else if (!href.startsWith("#")) {
        anchor.removeAttr("href");
      }
    }
    localizeDisplayText(clean.body());
    return clean.body().html();
  }

  private static void localizeDisplayText(Node node) {
    if (node instanceof Element element) {
      String tag = element.normalName();
      if (tag.equals("pre") || tag.equals("kbd") || tag.equals("samp")) return;
      if (tag.equals("code")) {
        // A command, expression or multi-token snippet is never a display-only enum.
        if (element.childNodeSize() == 1 && element.childNode(0) instanceof TextNode text) {
          String replacement = INTERNAL_EVIDENCE_ID.matcher(text.getWholeText()).matches()
              ? "相关证据" : INTERNAL_VALUES.get(text.getWholeText());
          if (replacement != null) text.text(replacement);
        }
        return;
      }
    }
    if (node instanceof TextNode text) {
      text.text(localizeText(text.getWholeText()));
      return;
    }
    for (Node child : node.childNodes()) localizeDisplayText(child);
  }

  private static String localizeText(String original) {
    Matcher urls = URL_PATTERN.matcher(original);
    StringBuilder localized = new StringBuilder();
    int offset = 0;
    while (urls.find()) {
      localized.append(localizeProse(original.substring(offset, urls.start())));
      localized.append(urls.group());
      offset = urls.end();
    }
    localized.append(localizeProse(original.substring(offset)));
    return localized.toString();
  }

  private static String localizeProse(String text) {
    String evidence = INTERNAL_EVIDENCE_REFERENCE.matcher(text).replaceAll("相关证据");
    String values = INTERNAL_VALUE_PATTERN.matcher(evidence)
        .replaceAll(match -> Matcher.quoteReplacement(INTERNAL_VALUES.get(match.group())));
    return INTERNAL_TERM_PATTERN.matcher(values)
        .replaceAll(match -> Matcher.quoteReplacement(INTERNAL_TERMS.get(match.group())));
  }
}
