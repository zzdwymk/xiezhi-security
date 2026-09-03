package com.bachelor.toolbox.recon;

import com.bachelor.toolbox.project.AssessmentProjectService;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.AuthorizedTargetRepository;
import com.bachelor.toolbox.target.TargetService;
import java.net.URI;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Manual, operator-assisted caption flow for the built-in MIIT ICP lookup. Because the MIIT portal
 * enforces a point / slider challenge that the server will not auto-guess (no model assets are
 * bundled), this endpoint lets an authorized operator view the challenge images in the UI and click
 * each matching character. The token, secret key and client uid never leave the server.
 */
@RestController
@RequestMapping("/api/projects/{projectId}/recon/icp")
public class IcpCaptchaController {

  private static final Logger log = LoggerFactory.getLogger(IcpCaptchaController.class);

  private final IcpChallengeStore challenges;
  private final IcpBrowserCaptureStore browserCaptures;
  private final AssessmentProjectService projectService;
  private final AuthorizedTargetRepository targets;
  private final TargetService targetService;

  /** 备案号（也兼容备案单位字段含「ICP备案编号」），例如「京ICP备12345678号」。 */
  private static final Pattern LICENSE_PATTERN =
      Pattern.compile(
          "[\\u4e00-\\u9fa5]{1,2}\\s*ICP\\s*(备案号|编号)?\\s*(备(?:案编号)?)?\\s*([A-Za-z0-9\\-()（）号]+)");

  private static final Pattern ACCESS_PATTERN =
      Pattern.compile(
          "([\\u4e00-\\u9fa5]{1,2}\\s*ICP\\s*(备案号|编号)?\\s*[A-Za-z0-9\\-()（）号]+)");

  private static final Pattern HOST_PATTERN =
      Pattern.compile("([a-zA-Z0-9][a-zA-Z0-9.-]*\\.[a-zA-Z]{2,}(?:\\.[a-zA-Z]{2,})?)");

  public IcpCaptchaController(
      IcpChallengeStore challenges,
      IcpBrowserCaptureStore browserCaptures,
      AssessmentProjectService projectService,
      AuthorizedTargetRepository targets,
      TargetService targetService) {
    this.challenges = challenges;
    this.browserCaptures = browserCaptures;
    this.projectService = projectService;
    this.targets = targets;
    this.targetService = targetService;
  }

  @PostMapping("/captcha")
  public Map<String, Object> begin(
      @PathVariable Long projectId, @RequestBody CaptchaBeginRequest request) {
    AuthorizedTarget target =
        targets
            .findById(request.targetId())
            .orElseThrow(() -> new IllegalArgumentException("未找到目标"));
    projectService.validateProjectTarget(projectId, request.targetId());
    targetService.getCurrentlyAuthorized(request.targetId(), projectId);

    MiitIcpClient client = new MiitIcpClient(new com.fasterxml.jackson.databind.ObjectMapper());
    MiitIcpClient.PendingCaptcha pending = client.beginChallenge();
    String challengeId = challenges.register(pending);

    Map<String, Object> response = new LinkedHashMap<>();
    response.put("challengeId", challengeId);
    response.put("domain", hostOf(target.getTargetValue()));
    response.put("image", pending.bigImage());
    response.put("characterStrip", pending.smallImage());
    response.put("message", "请在大图中按顺序点击字符条中每个字符的位置");
    return response;
  }

  private String hostOf(String raw) {
    try {
      String value = raw.matches("^[a-zA-Z][a-zA-Z0-9+.-]*://.*") ? raw : "//" + raw;
      URI uri = URI.create(value);
      return uri.getHost();
    } catch (Exception exception) {
      return null;
    }
  }

  @PostMapping("/captcha/verify")
  public Map<String, Object> verify(
      @PathVariable Long projectId, @RequestBody VerifiedRequest request) {
    AuthorizedTarget target =
        targets
            .findById(request.targetId())
            .orElseThrow(() -> new IllegalArgumentException("未找到目标"));
    projectService.validateProjectTarget(projectId, request.targetId());
    targetService.getCurrentlyAuthorized(request.targetId(), projectId);
    String domain = hostOf(target.getTargetValue());
    if (domain == null) {
      throw new IllegalArgumentException("目标中没有可查询的域名");
    }

    MiitIcpClient.PendingCaptcha pending = challenges.take(request.challengeId());
    if (pending == null) {
      Map<String, Object> error = resultOf("CAPTCHA_REQUIRED", "验证会话已失效或已过期，请重新发起");
      error.put("domain", domain);
      return error;
    }

    MiitIcpClient.MiitResult result =
        new MiitIcpClient(new com.fasterxml.jackson.databind.ObjectMapper())
            .submitPoints(pending, normalizePoints(request.points()), domain);

    Map<String, Object> response = new LinkedHashMap<>();
    response.put("domain", domain);
    if (result.success()) {
      response.put("status", "AVAILABLE");
      response.put("source", "miit-manual-captcha");
      response.put("records", mapRecords(result.records));
      response.put("total", result.total);
    } else if (result.wasBlockedByCaptcha()) {
      response.put("status", "CAPTCHA_REQUIRED");
      response.put("reason", result.reason);
    } else {
      response.put("status", "UNAVAILABLE");
      response.put("reason", result.reason);
    }
    return response;
  }

  /**
   * Accepts the records an operator captured from the live MIIT query page in the desktop browser
   * assistant and returns them in the same shape as the batch / manual verify result, so the UI can
   * render them identically. The records are not executed against the target; they are only the
   * already-verified rows the operator chose to import.
   */
  @PostMapping("/browser/capture")
  public Map<String, Object> capture(
      @PathVariable Long projectId, @RequestBody BrowserCaptureRequest request) {
    AuthorizedTarget target =
        targets
            .findById(request.targetId())
            .orElseThrow(() -> new IllegalArgumentException("未找到目标"));
    projectService.validateProjectTarget(projectId, request.targetId());
    targetService.getCurrentlyAuthorized(request.targetId(), projectId);
    String domain = hostOf(target.getTargetValue());
    if (domain == null) {
      throw new IllegalArgumentException("目标中没有可查询的域名");
    }

    Map<String, Object> response = new LinkedHashMap<>();
    response.put("domain", domain);
    response.put("status", "AVAILABLE");
    response.put("source", "miit-browser-capture");
    List<Map<String, Object>> rows = new ArrayList<>();
    Set<String> seenKeys = new HashSet<>();
    // Combine all captured fragments into one blob so per-record secondary fields
    // (审核通过日期 / 主办单位性质 / 服务前置审批项) can be filled when the DOM cut
    // them into separate nodes.
    StringBuilder blobBuilder = new StringBuilder();
    if (request.records() != null) {
      for (Map<String, Object> raw : request.records()) {
        for (String cell : cellsOf(raw)) blobBuilder.append(cell).append(' ');
        String text = nonBlank(raw, "text");
        if (!text.isBlank()) blobBuilder.append(text).append('\n');
      }
    }
    String blob = blobBuilder.toString();

    if (request.records() != null) {
      for (Map<String, Object> raw : request.records()) {
        Map<String, Object> row = browserRow(raw, domain, blob);
        if (row == null) continue; // junk / header / empty fragment
        String licenseKey =
            String.valueOf(row.get("mainLicense")).isBlank()
                ? String.valueOf(row.get("serviceLicense")).isBlank()
                    ? String.valueOf(row.get("owner")) + "|" + String.valueOf(row.get("domain"))
                    : "svc:" + String.valueOf(row.get("serviceLicense"))
                : "lic:" + String.valueOf(row.get("mainLicense"));
        String key =
            String.valueOf(row.get("domain"))
                + "|"
                + licenseKey
                + "|"
                + String.valueOf(row.get("owner"))
                + "|"
                + String.valueOf(row.get("approveDate"));
        if (seenKeys.add(key)) {
          rows.add(row);
        }
      }
    }
    browserCaptures.store(projectId, request.targetId(), domain, rows);
    log.info("[icp-capture] domain={} targetId={} received={} stored={}", domain,
        request.targetId(),
        request.records() == null ? 0 : request.records().size(), rows.size());
    response.put("records", rows);
    response.put("total", rows.size());
    return response;
  }

  /**
   * Maps one raw captured row onto the canonical record fields. The desktop assistant returns
   * mostly free-text (cells/text), so each field prefers an explicit key, otherwise a column cell,
   * otherwise a regex-parsed value from the joined text.
   */
  private Map<String, Object> browserRow(Map<String, Object> raw, String queriedDomain, String blob) {
    String owner = firstNonBlank(raw, "owner", "unitName");
    String domain = firstNonBlank(raw, "domain", "domain");
    String mainLicense = firstNonBlank(raw, "mainLicense", "mainLicence");
    String serviceLicense = firstNonBlank(raw, "serviceLicense", "serviceLicence");
    String type = firstNonBlank(raw, "type", "natureName");
    String approvedContent = firstNonBlank(raw, "approvedContent", "contentTypeName");
    String limitAccess = firstNonBlank(raw, "limitAccess");
    String approveDate = normalizeApprovalDateTime(firstNonBlank(raw, "approveDate", "updateRecordTime"));

    String text = stringOf(raw, "text");
    List<String> cells = cellsOf(raw);
    String joined = text.isBlank() ? String.join(" | ", cells) : text;
    String label = joined.toLowerCase(Locale.ROOT);

    // The MIIT detail row is "标签：值" pairs (ICP备案/许可证号：/审核通过日期：/
    // 主办单位名称：/主办单位性质：/服务前置审批项：/网站域名：…). Prefer label-aware
    // extraction so the value lands in the right field instead of an index cell guess.
    String labelOwner = labelValue(joined, List.of("主办单位名称", "主办单位", "主办方"));
    String labelLicense = labelValue(joined, List.of("ICP备案/许可证号", "备案/许可证号", "ICP备案号"));
    String labelDomain = labelValue(joined, List.of("网站域名", "域名"));
    String labelDate = labelValue(joined, List.of("审核通过日期", "审核日期", "备案日期"));
    String labelType = labelValue(joined, List.of("主办单位性质", "备案性质"));
    String labelPreApproval = labelValue(joined, List.of("服务前置审批项", "前置审批项"));

    if (owner.isBlank()) owner = labelOwner;
    // main + 服务许可证号 are number-bounded (…号), so prefer the regex extractor:
    // labelValue over-runs into the following date when the DOM glues them without a colon.
    if (mainLicense.isBlank()) {
      mainLicense = licenseOf(joined, label);
      if (mainLicense.isBlank()) mainLicense = labelLicense;
    }
    if (approveDate.isBlank()) {
      approveDate = dateOf(joined);
      if (approveDate.isBlank()) approveDate = labelDate;
    }
    if (type.isBlank()) type = labelType;
    if (approvedContent.isBlank()) approvedContent = labelPreApproval;
    if (limitAccess.isBlank()) limitAccess = labelPreApproval;

    if (owner.isBlank()) {
      owner = labeled(joined, List.of("单位名称", "主办单位", "主办方", "法人/企业"));
      if (owner.isBlank()) owner = firstNameLikeCell(cells);
    }
    if (mainLicense.isBlank()) {
      mainLicense = licenseOf(joined, label);
      if (mainLicense.isBlank()) {
        for (String cell : cells) {
          String found = licenseOf(cell, cell.toLowerCase(Locale.ROOT));
          if (!found.isBlank()) {
            mainLicense = found;
            break;
          }
        }
      }
    }
    if (type.isBlank()) {
      if (label.contains("企业") || label.contains("单位")) type = "企业/单位";
      else if (label.contains("网站")) type = "网站";
    }
    if (domain.isBlank()) {
      if (!labelDomain.isBlank()) domain = labelDomain;
      else {
        Matcher hostMatch = HOST_PATTERN.matcher(joined);
        if (hostMatch.find()) domain = hostMatch.group(1);
      }
    }
    // Normalize the resolved domain and reduce any subdomain of the queried root back
    // to that root (www./cn./m./app. … variants), so brief/matching are consistent.
    domain = normalizeDomain(domain);
    if (domain.isBlank()) domain = normalizeDomain(queriedDomain);
    String rootDomain = normalizeDomain(queriedDomain);
    if (!domain.isBlank() && !domain.equals(rootDomain)
        && domain.endsWith("." + rootDomain)) {
      domain = rootDomain;
    }
    if (approveDate.isBlank() && cells.size() > 1) {
      String last = cells.get(cells.size() - 1).trim();
      if (last.matches(".*(\\d{4}[-/年.]\\d{1,2}[-/月.]\\d{1,2}日?).*")) approveDate = last;
    }

    // Enrich fields the DOM may have split into a separate fragment: parse the combined
    // detail blob for 审核通过日期 / 主办单位性质 / 服务前置审批项 / 主办单位名称 when this
    // particular row carries an incomplete copy.
    if (blob != null && !blob.isBlank()) {
      // The DOM can glue the value onto the label without a "：" nor "|" (separate nodes), so
      // prefer the shape-agnostic extractors first: dateOf finds the 4-digit date anywhere, and
      // labelValue still fills the rest from their label token.
      if (approveDate.isBlank()) approveDate = dateOf(blob);
      if (approveDate.isBlank()) approveDate = sanitizeValue(labelValue(blob, List.of("审核通过日期", "审核日期", "备案日期")));
      if (type.isBlank()) type = sanitizeValue(labelValue(blob, List.of("主办单位性质", "备案性质")));
      if (approvedContent.isBlank()) approvedContent = sanitizeValue(labelValue(blob, List.of("服务前置审批项", "前置审批项")));
      if (owner.isBlank()) owner = sanitizeValue(labelValue(blob, List.of("主办单位名称", "主办单位", "主办方")));
    }

    // Guard against junk fragments: the DOM scan can emit header/action rows whose only
    // content is a known field label ("主办单位性质", "操作", …) or nothing. Drop rows
    // that carry no real owner and no license (they aren't ICP records).
    if (isLabelToken(owner)) owner = "";
    if (isLabelToken(type)) type = "";
if (isLabelToken(approveDate)) approveDate = "";
    // A real approval date is always a 4-digit-year run; anything else is header/action junk.
    if (!approveDate.isBlank() && !approveDate.matches("(?s).*?\\d{4}[-/年.]\\d{1,2}.*")) approveDate = "";
    // Re-anchor licenses so a greedy scan cannot carry junk/leading chars or a glued date.
    mainLicense = cleanLicense(mainLicense);
    serviceLicense = cleanLicense(serviceLicense);
    // A real ICP row carries at least a 备案号 or an owner. Only drop header/action/empty
    // fragment rows that are blank in every field; keep a row if it has any usable content so a
    // page with unparseable-but-present records does not silently import 0.
    if (mainLicense.isBlank()
        && serviceLicense.isBlank()
        && owner.isBlank()
        && approveDate.isBlank()) return null;

    Map<String, Object> row = new LinkedHashMap<>();
    row.put("owner", owner);
    row.put("domain", domain);
    row.put("mainLicense", mainLicense);
    row.put("serviceLicense", serviceLicense);
    row.put("type", type);
    row.put("approvedContent", approvedContent);
    row.put("limitAccess", limitAccess);
    row.put("approveDate", approveDate);
    return row;
  }

  private boolean isLabelToken(String value) {
    if (value == null || value.isBlank()) return false;
    return LABEL_TOKENS.contains(value.trim());
  }

  private String sanitizeValue(String value) {
    if (value == null) return "";
    String v = value.trim();
    if (v.isEmpty()) return "";
    if (isLabelToken(v)) return "";
    return v;
  }

  private String nonBlank(Map<String, Object> row, String key) {
    String value = stringOf(row, key);
    return value == null ? "" : value.trim();
  }

  /** First non-blank value across a list of aliases (desktop free keys + MIIT API keys). */
  private String firstNonBlank(Map<String, Object> row, String... keys) {
    for (String key : keys) {
      String value = nonBlank(row, key);
      if (!value.isBlank()) return value;
    }
    return "";
  }

  /** The MIIT API returns "2020-06-03 14:29:05"; keep only the date part for display. */
  private String normalizeApprovalDateTime(String raw) {
    if (raw == null || raw.isBlank()) return raw;
    String value = raw.trim();
    Matcher m = DATE_PATTERN.matcher(value);
    if (m.find()) return m.group();
    return value;
  }

  private List<String> cellsOf(Map<String, Object> row) {
    Object value = row == null ? null : row.get("cells");
    List<String> result = new ArrayList<>();
    if (value instanceof List<?> list) {
      for (Object item : list) {
        if (item != null) result.add(String.valueOf(item).trim());
      }
    }
    return result;
  }

  /**
   * The MIIT result list typically starts with an 序号 (index) column holding plain numbers.
   * Pick the first cell that is not purely numeric and not an ICP license, so we do not mistake
   * the row index "1" for the 主办单位 name.
   */
  private String firstNameLikeCell(List<String> cells) {
    if (cells == null) return "";
    for (String cell : cells) {
      String value = cell == null ? "" : cell.trim();
      if (value.isEmpty()) continue;
      if (value.matches("[0-9]+")) continue;
      if (value.matches(".*ICP\\s*(备案号|编号)?.*")) continue;
      return value;
    }
    return "";
  }

  /**
   * Extracts the value that follows a "标签：" prefix, e.g. given
   * "ICP备案/许可证号：京ICP备12345678号-1" and key "ICP备案/许可证号" returns
   * "京ICP备12345678号-1". The value runs until the next label terminator
   * ("|" or a following "：label" such as a date or another detail label).
   */
  private String labelValue(String text, List<String> keys) {
    if (text == null || text.isBlank()) return "";
    for (String key : keys) {
      int idx = text.indexOf(key);
      if (idx < 0) continue;
      int start = idx + key.length();
      // Skip an optional ":：" immediately after the label.
      while (start < text.length()) {
        char c = text.charAt(start);
        if (c == '：' || c == ':' || c == ' ' || c == '\n' || c == '\t') start++;
        else break;
      }
      int end = start;
      while (end < text.length()) {
        char c = text.charAt(end);
        if (c == '|' || c == '\n' || c == '\t') break;
        // Stop at the next "label：" token so a following field isn't swallowed.
        if ((c == '：' || c == ':')
            && end + 1 < text.length()
            && (Character.isLetter(text.charAt(end + 1)) || text.charAt(end + 1) == ' ')) {
          break;
        }
        // Dense DOM nodes may glue the value straight into the next label (no trailing delimiter).
        // Stop as soon as a known field label starts and we already have content.
        if (end > start && startsWithLabelToken(text, end)) break;
        end++;
      }
      String value = text.substring(start, end).trim();
      if (!value.isBlank()) return value;
    }
    return "";
  }

  private boolean startsWithLabelToken(String text, int from) {
    for (String token : LABEL_TOKENS) {
      if (from + token.length() <= text.length()
          && text.regionMatches(from, token, 0, token.length())) {
        return true;
      }
    }
    return false;
  }

  /**
   * Normalizes a captured/host domain to the canonical form the ICP query page itself uses:
   * lower-cases, strips scheme / userinfo / port / path, and drops a leading {@code www.}.
   */
  private String normalizeDomain(String raw) {
    if (raw == null) return "";
    String value = raw.trim().toLowerCase(Locale.ROOT);
    if (value.isEmpty()) return "";
    if (value.matches("^[a-z0-9+.-]+://.*")) {
      try {
        value = URI.create(value).getHost();
      } catch (Exception exception) {
        value = value.replaceFirst("^[a-z0-9+.-]+://", "");
      }
    }
    int at = value.lastIndexOf('@');
    if (at >= 0) value = value.substring(at + 1);
    int port = value.indexOf(':');
    if (port >= 0) value = value.substring(0, port);
    int path = value.indexOf('/');
    if (path >= 0) value = value.substring(0, path);
    value = value.replaceAll("^www\\.", "").replaceAll("\\.$", "");
    // ICP is registered per registerable domain: strip a leading single-label
    // content/locale/CDN prefix (cn., m., mobile., app., …) so cn.bing.com -> bing.com.
    String[] labels = value.split("\\.");
    if (labels.length >= 3 && CONTENT_PREFIX.contains(labels[0])) {
      String reduced = value.substring(value.indexOf('.') + 1);
      if (reduced.contains(".")) return reduced;
    }
    return value;
  }

  private static final Set<String> CONTENT_PREFIX =
      Set.of(
          "www", "m", "mobile", "wap", "app", "apps", "api", "apiv2", "apiv3",
          "static", "cdn", "img", "image", "web", "www2",
          "cn", "en", "de", "fr", "es", "it", "jp", "kr", "ru", "pt", "br", "mx",
          "in", "au", "sg", "my", "id", "vn", "th", "ph", "tw", "hk", "global", "world");

  private static final Set<String> LABEL_TOKENS =
      Set.of(
          "主办单位性质", "主办单位名称", "单位名称", "主办单位", "主办方", "ICP备案/许可证号",
          "ICP备案号", "备案/许可证号", "审核通过日期", "审核日期", "备案日期", "网站域名", "域名",
          "服务前置审批项", "前置审批项", "操作", "奖励", "许可证", "办理机构", "网站首页", "网站");

  private String labeled(String text, List<String> keys) {
    if (text == null || text.isBlank()) return "";
    for (String key : keys) {
      int idx = text.indexOf(key);
      if (idx < 0) continue;
      int start = idx + key.length();
      int end = text.indexOf('|', start);
      end = end < 0 ? text.length() : end;
      String value = text.substring(start, end).replaceAll("^[：:\\s]+|[\\s|]+$", "");
      if (!value.isBlank()) return value;
    }
    return "";
  }

  /** 备案号格式，例如「京 ICP 备 12345678 号」或「京ICP备12345678号」。 */
  private String licenseOf(String text, String label) {
    if (text == null || text.isBlank()) return "";
    Matcher license = LICENSE_PATTERN.matcher(text);
    if (license.find()) return license.group();
    if (label.contains("icp")) {
      Matcher access = ACCESS_PATTERN.matcher(text);
      if (access.find()) return access.group();
    }
    return "";
  }

  /** Date like 2020-06-03, 2020/6/3, 2020年6月3日. Both separators are required so a bare
   * 8-digit license run (…ICP备13002172000号…) can never match. */
  private static final Pattern DATE_PATTERN =
      Pattern.compile("\\d{4}[-/年：.]\\d{1,2}[-/月.:]\\d{1,2}日?");

  private String dateOf(String text) {
    if (text == null || text.isBlank()) return "";
    Matcher m = DATE_PATTERN.matcher(text);
    if (m.find()) return m.group();
    return "";
  }

  /** Leading region markers of a valid 备案号 (province single-char codes). */
  private static final java.util.Set<Character> PROVINCE_CODES =
      java.util.Set.of(
          '京', '沪', '津', '渝', '冀', '晋', '蒙', '辽', '吉', '黑', '苏', '浙',
          '皖', '闽', '赣', '鲁', '豫', '鄂', '湘', '粤', '桂', '琼', '川', '黔',
          '贵', '滇', '云', '藏', '陕', '甘', '青', '宁', '新');

  /**
   * Post-cleans a rawly extracted 备案号. The scanning regex is deliberately greedy, so it can
   * glue a following field (e.g. a 审核通过日期 "2020-06-03" with no trailing colon) onto the
   * license, or pick up a leading stray province/junk character. Re-anchor to the "ICP备" mark,
   * drop junk before it, and cut anything glued on after a 4-digit-year date run.
   */
  private String cleanLicense(String license) {
    if (license == null) return "";
    String v = license.trim();
    // Cut a glued date (and anything after it) that runs straight into the number.
    Matcher d = Pattern.compile("\\d{4}[-/年.]\\d{1,2}").matcher(v);
    if (d.find()) v = v.substring(0, d.start()).trim();
    // Re-anchor to the ICP mark, keeping at most the single province char before it.
    int idx = Math.max(v.lastIndexOf("ICP备"), v.lastIndexOf("ICP"));
    if (idx < 0) idx = v.indexOf("备");
    if (idx > 0 && PROVINCE_CODES.contains(v.charAt(idx - 1))) idx--;
    if (idx >= 0) v = v.substring(idx);
    // Leave no bare separator at the end.
    return v.trim().replaceAll("[\\-－\\s]+$", "");
  }

  private String stringOf(Map<String, Object> row, String key) {
    Object value = row == null ? null : row.get(key);
    return value == null ? "" : String.valueOf(value);
  }

  private List<Map<String, Object>> mapRecords(List<IcpRecord> records) {
    List<Map<String, Object>> rows = new ArrayList<>();
    for (IcpRecord record : records) {
      Map<String, Object> row = new LinkedHashMap<>();
      row.put("owner", record.owner());
      row.put("domain", record.domain());
      row.put("mainLicense", record.mainLicense());
      row.put("serviceLicense", record.serviceLicense());
      row.put("type", record.type());
      row.put("approvedContent", record.approvedContent());
      row.put("limitAccess", record.limitAccess());
      row.put("approveDate", record.approveDate());
      rows.add(row);
    }
    return rows;
  }

  private Map<String, Object> resultOf(String status, String reason) {
    Map<String, Object> result = new LinkedHashMap<>();
    result.put("status", status);
    result.put("reason", reason);
    return result;
  }

  private List<Map<String, Object>> normalizePoints(List<Map<String, Object>> raw) {
    List<Map<String, Object>> points = new ArrayList<>();
    if (raw == null) {
      return points;
    }
    for (Map<String, Object> candidate : raw) {
      Object xRaw = candidate.get("x");
      Object yRaw = candidate.get("y");
      if (xRaw instanceof Number x && yRaw instanceof Number y) {
        Map<String, Object> point = new LinkedHashMap<>();
        point.put("x", x.intValue());
        point.put("y", y.intValue());
        points.add(point);
      }
    }
    return points;
  }

  public record CaptchaBeginRequest(Long targetId) {}

  public record VerifiedRequest(Long targetId, String challengeId, List<Map<String, Object>> points) {}

  public record BrowserCaptureRequest(Long targetId, List<Map<String, Object>> records) {}
}