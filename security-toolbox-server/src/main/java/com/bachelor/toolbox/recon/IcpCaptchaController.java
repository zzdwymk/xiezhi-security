package com.bachelor.toolbox.recon;

import com.bachelor.toolbox.project.AssessmentProjectService;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.AuthorizedTargetRepository;
import com.bachelor.toolbox.target.TargetService;
import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Manual, operator-assisted caption flow for the built-in MIIT ICP lookup. Because the MIIT portal
 * enforces a point / slider challenge that the server will not auto-guess (no model assets are
 * bundled), this endpoint lets an authorized operator view the challenge images in the UI and click
 * each matching character. The token, secret key and client uid never leave the server.
 */
@RestController
@RequestMapping("/api/projects/{projectId}/recon/icp")
public class IcpCaptchaController {

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
    if (request.records() != null) {
      for (Map<String, Object> raw : request.records()) {
        rows.add(browserRow(raw, domain));
      }
    }
    browserCaptures.store(projectId, request.targetId(), domain, rows);
    response.put("records", rows);
    response.put("total", rows.size());
    return response;
  }

  /**
   * Maps one raw captured row onto the canonical record fields. The desktop assistant returns
   * mostly free-text (cells/text), so each field prefers an explicit key, otherwise a column cell,
   * otherwise a regex-parsed value from the joined text.
   */
  private Map<String, Object> browserRow(Map<String, Object> raw, String queriedDomain) {
    String owner = nonBlank(raw, "owner");
    String domain = nonBlank(raw, "domain");
    String mainLicense = nonBlank(raw, "mainLicense");
    String serviceLicense = nonBlank(raw, "serviceLicense");
    String type = nonBlank(raw, "type");
    String approvedContent = nonBlank(raw, "approvedContent");
    String limitAccess = nonBlank(raw, "limitAccess");
    String approveDate = nonBlank(raw, "approveDate");

    String text = stringOf(raw, "text");
    List<String> cells = cellsOf(raw);
    String joined = text.isBlank() ? String.join(" ", cells) : text;
    String label = joined.toLowerCase(Locale.ROOT);

    if (owner.isBlank()) {
      owner = labeled(joined, List.of("单位名称", "主办单位", "主办方", "法人/企业"));
      if (owner.isBlank() && !cells.isEmpty()) owner = cells.get(0);
    }
    if (mainLicense.isBlank()) {
      mainLicense = licenseOf(joined, label);
    }
    if (type.isBlank()) {
      if (label.contains("企业") || label.contains("单位")) type = "企业/单位";
      else if (label.contains("网站")) type = "网站";
    }
    if (domain.isBlank()) {
      Matcher hostMatch = HOST_PATTERN.matcher(joined);
      if (hostMatch.find()) domain = hostMatch.group(1);
      if (domain.isBlank()) domain = queriedDomain;
    }
    if (approveDate.isBlank() && cells.size() > 1) {
      String last = cells.get(cells.size() - 1).trim();
      if (last.matches(".*(\\d{4}[-/年.]\\d{1,2}[-/月.]\\d{1,2}日?).*")) approveDate = last;
    }

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

  private String nonBlank(Map<String, Object> row, String key) {
    String value = stringOf(row, key);
    return value == null ? "" : value.trim();
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

  public record BrowserCaptureRequest(
      Long targetId, List<Map<String, Object>> records) {}
}