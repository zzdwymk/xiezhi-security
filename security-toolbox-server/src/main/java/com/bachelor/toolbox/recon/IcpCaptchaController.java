package com.bachelor.toolbox.recon;

import com.bachelor.toolbox.project.AssessmentProjectService;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.AuthorizedTargetRepository;
import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
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
  private final AssessmentProjectService projectService;
  private final AuthorizedTargetRepository targets;

  public IcpCaptchaController(
      IcpChallengeStore challenges,
      AssessmentProjectService projectService,
      AuthorizedTargetRepository targets) {
    this.challenges = challenges;
    this.projectService = projectService;
    this.targets = targets;
  }

  @PostMapping("/captcha")
  public Map<String, Object> begin(
      @PathVariable Long projectId, @RequestBody CaptchaBeginRequest request) {
    AuthorizedTarget target =
        targets
            .findById(request.targetId())
            .orElseThrow(() -> new IllegalArgumentException("未找到目标"));
    projectService.validateProjectTarget(projectId, request.targetId());

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
}