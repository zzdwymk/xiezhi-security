package com.bachelor.toolbox.recon;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Built-in client for the official MIIT ICP filing portal (beian.miit.gov.cn). This mirrors the
 * public protocol used by community projects such as openeasm/ICP-API without depending on a
 * third-party lookup service: the server performs the auth handshake, obtains the verification
 * image challenge and, when a signature can be established, queries the abbreviation list.
 *
 * <p>Because the MIIT portal enforces a point / slider challenge, this implementation performs a
 * deterministic single-pass attempt and reports a typed {@code CAPTCHA_REQUIRED} outcome when the
 * challenge cannot be satisfied automatically, so the coordinator can fall back to a trusted
 * manually configured API.
 */
final class MiitIcpClient {
  private static final Logger log = LoggerFactory.getLogger(MiitIcpClient.class);

  private static final String BASE_URL = "https://hlwicpfwc.miit.gov.cn";
  private static final String REFERER = "https://beian.miit.gov.cn/";
  private static final String AUTH_PATH = "/icpproject_query/api/auth";
  private static final String POINT_IMAGE_PATH = "/icpproject_query/api/image/getCheckImagePoint";
  private static final String CHECK_IMAGE_PATH = "/icpproject_query/api/image/checkImage";
  private static final String QUERY_PATH =
      "/icpproject_query/api/icpAbbreviateInfo/queryByCondition";
  private static final String USER_AGENT =
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
          + "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36";

  /** Channel key used by the public MIIT ICP query gateway. */
  private static final String AUTH_KEY = "testtest";

  private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(8);
  private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(12);

  private final ObjectMapper json;
  private final HttpClient client;
  private final String modelsPath;

  MiitIcpClient(ObjectMapper json) {
    this(json, null);
  }

  MiitIcpClient(ObjectMapper json, String modelsPath) {
    this.json = json;
    this.modelsPath = modelsPath;
    this.client =
        HttpClient.newBuilder()
            .connectTimeout(CONNECT_TIMEOUT)
            .version(HttpClient.Version.HTTP_1_1)
            .followRedirects(HttpClient.Redirect.NEVER)
            .build();
  }

  public MiitResult queryByUnit(String unit) {
    try {
      String accessToken = authenticate();
      String clientUid = "point-" + UUID.randomUUID();
      Challenge challenge = fetchChallenge(accessToken, clientUid);
      String sign = verify(challenge, accessToken);
      return queryRecords(unit, sign, challenge.uuid(), accessToken);
    } catch (MiitCaptchaRequiredException exception) {
      log.info("MIIT 点选验证无法自动完成，需回退手动数据源，domain={}", unit);
      return MiitResult.captchaRequired(exception.getMessage());
    } catch (MiitException exception) {
      log.warn("MIIT 直接查询失败，domain={}", unit, exception);
      return MiitResult.failure(exception.getMessage());
    } catch (Exception exception) {
      log.warn("MIIT 直接查询意外失败，domain={}", unit, exception);
      return MiitResult.failure("工信部备案查询服务暂不可用");
    }
  }

  /**
   * Starts a manual point-challenge session: performs the auth handshake and the verification
   * image request, and returns the pending state (including the images the operator needs to
   * locate the matching characters). The token, secret key and client uid remain server-side.
   */
  public PendingCaptcha beginChallenge() {
    try {
      String accessToken = authenticate();
      String clientUid = "point-" + UUID.randomUUID();
      Challenge challenge = fetchChallenge(accessToken, clientUid);
      return new PendingCaptcha(
          accessToken,
          challenge.uuid(),
          challenge.secretKey(),
          challenge.clientUid(),
          challenge.bigImage(),
          challenge.smallImage());
    } catch (MiitException exception) {
      log.warn("MIIT 手工验证会话启动失败", exception);
      throw exception;
    } catch (Exception exception) {
      log.warn("MIIT 手工验证会话启动失败", exception);
      throw new MiitException("MIIT 手工验证会话启动失败", exception);
    }
  }

  /**
   * Completes a manual point challenge with operator-selected coordinates. The selected points
   * are encrypted with the server-side secret, exchanged for a sign, then the query is run.
   */
  public MiitResult submitPoints(PendingCaptcha pending, List<Map<String, Object>> points, String unit) {
    if (pending == null || points == null || points.isEmpty()) {
      return MiitResult.failure("无效的验证会话或点击坐标");
    }
    if (pending.secretKey() == null || pending.secretKey().isBlank()) {
      return MiitResult.failure("MIIT 当前接口未返回 secretKey，点选验证校验不可用");
    }
    try {
      String pointJson = aesEcbEncrypt(compactPoints(points), pending.secretKey());
      String body =
          json.writeValueAsString(
              Map.of(
                  "token", pending.uuid(),
                  "secretKey", pending.secretKey(),
                  "clientUid", pending.clientUid(),
                  "pointJson", pointJson));
      JsonNode response = postJson(CHECK_IMAGE_PATH, pending.token(), body);
      if (response.path("code").asInt(-1) != 200) {
        return MiitResult.failure("MIIT 点选验证校验失败，请重试");
      }
      String sign = response.path("params").path("sign").asText("");
      if (sign.isBlank()) {
        return MiitResult.failure("MIIT 验证后未返回签名，请重试");
      }
      return queryRecords(unit, sign, pending.uuid(), pending.token());
    } catch (MiitCaptchaRequiredException exception) {
      return MiitResult.captchaRequired(exception.getMessage());
    } catch (MiitException exception) {
      log.warn("MIIT 手工验证提交失败，domain={}", unit, exception);
      return MiitResult.failure(exception.getMessage());
    } catch (Exception exception) {
      log.warn("MIIT 手工验证提交意外失败，domain={}", unit, exception);
      return MiitResult.failure("工信部备案查询服务暂不可用");
    }
  }

  private String authenticate() throws IOException, InterruptedException {
    String timestamp = String.valueOf(System.currentTimeMillis() / 1000);
    String authKey = md5Hex(AUTH_KEY + timestamp);
    // The MIIT auth gate expects form-urlencoded key=value pairs (authKey, timeStamp), not JSON.
    String body = "authKey=" + authKey + "&timeStamp=" + timestamp;
    JsonNode response = postForm(AUTH_PATH, body);
    String token = response.path("params").path("bussiness").asText("");
    if (token.isBlank()) {
      throw new MiitException("MIIT 未返回访问令牌");
    }
    return token;
  }

  private Challenge fetchChallenge(String accessToken, String clientUid)
      throws IOException, InterruptedException {
    String body = json.writeValueAsString(Map.of("clientUid", clientUid));
    JsonNode response = postJson(POINT_IMAGE_PATH, accessToken, body);
    if (response.path("code").asInt(-1) != 200) {
      throw new MiitException("MIIT 获取验证码失败");
    }
    // The current (2025+) MIIT gateway returns the challenge fields at the top level
    // (bigImage, smallImage, uuid, height); the older reference returned them nested under
    // params plus a secretKey. Read the top level first and fall back to params so both shapes
    // are tolerated.
    String uuid = text(response, "uuid");
    String bigImage = text(response, "bigImage");
    String smallImage = text(response, "smallImage");
    String secretKey = text(response, "secretKey");
    if (uuid.isBlank() || bigImage.isBlank()) {
      throw new MiitException("MIIT 验证码参数不完整");
    }
    return new Challenge(uuid, secretKey, bigImage, smallImage, clientUid);
  }

  /** Reads a string field, preferring the top-level object then the nested {@code params}. */
  private static String text(JsonNode response, String key) {
    String v = response.path(key).asText("");
    if (v.isBlank()) {
      v = response.path("params").path(key).asText("");
    }
    return v;
  }

  private void requireSecret(String challengeSecret, String message) throws MiitException {
    if (challengeSecret == null || challengeSecret.isBlank()) {
      throw new MiitException(message);
    }
  }

  private String verify(Challenge challenge, String accessToken)
      throws IOException, InterruptedException, MiitCaptchaRequiredException {
    requireSecret(challenge.secretKey(), "MIIT 点选验证无法完成（当前接口未返回 secretKey）");
    List<Map<String, Object>> solved =
        MiitCaptchaSolver.solve(challenge.bigImage(), challenge.smallImage(), modelsPath);
    if (solved == null) {
      throw new MiitCaptchaRequiredException("MIIT 点选验证无法自动完成，请配置手动数据源");
    }
    String pointJson = aesEcbEncrypt(compactPoints(solved), challenge.secretKey());
    String body =
        json.writeValueAsString(
            Map.of(
                "token", challenge.uuid(),
                "secretKey", challenge.secretKey(),
                "clientUid", challenge.clientUid(),
                "pointJson", pointJson));
    JsonNode response = postJson(CHECK_IMAGE_PATH, accessToken, body);
    if (response.path("code").asInt(-1) != 200) {
      throw new MiitException("MIIT 点选验证校验失败");
    }
    String sign = response.path("params").path("sign").asText("");
    if (sign.isBlank()) {
      throw new MiitException("MIIT 验证后未返回签名");
    }
    return sign;
  }

  private MiitResult queryRecords(String unit, String sign, String uuid, String accessToken)
      throws IOException, InterruptedException {
    String body =
        json.writeValueAsString(
                Map.of("pageNum", "", "pageSize", "1500", "unitName", unit, "serviceType", 1))
            .replace(" ", "");
    JsonNode response = postQuery(QUERY_PATH, sign, uuid, accessToken, body);
    if (response.path("code").asInt(-1) != 200) {
      return MiitResult.failure("MIIT 返回 " + response.path("msg").asText("查询失败"));
    }
    JsonNode list = response.path("params").path("list");
    List<IcpRecord> records = new ArrayList<>();
    if (list.isArray()) {
      for (JsonNode row : list) {
        records.add(
            new IcpRecord(
                row.path("unitName").asText(""),
                row.path("domain").asText(""),
                row.path("mainLicence").asText(""),
                row.path("serviceLicence").asText(""),
                row.path("natureName").asText(""),
                row.path("contentTypeName").asText(""),
                row.path("limitAccess").asText(""),
                row.path("updateRecordTime").asText("")));
      }
    }
    return MiitResult.success(records, response.path("params").path("total").asInt(records.size()));
  }

  private String md5Hex(String value) {
    try {
      MessageDigest digest = MessageDigest.getInstance("MD5");
      byte[] bytes = digest.digest(value.getBytes(StandardCharsets.UTF_8));
      StringBuilder builder = new StringBuilder(bytes.length * 2);
      for (byte b : bytes) {
        builder.append(String.format("%02x", b));
      }
      return builder.toString();
    } catch (Exception exception) {
      throw new MiitException("无法生成 MIIT 鉴权摘要", exception);
    }
  }

  private static String aesEcbEncrypt(String plaintext, String secretKey) {
    try {
      SecretKeySpec key = new SecretKeySpec(secretKey.getBytes(StandardCharsets.UTF_8), "AES");
      Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
      cipher.init(Cipher.ENCRYPT_MODE, key);
      byte[] encrypted = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
      return Base64.getEncoder().encodeToString(encrypted);
    } catch (Exception exception) {
      throw new MiitException("MIIT 验证码数据加密失败", exception);
    }
  }

  private static String compactPoints(List<Map<String, Object>> points) {
    StringBuilder builder = new StringBuilder("[");
    for (int index = 0; index < points.size(); index++) {
      if (index > 0) builder.append(",");
      Map<String, Object> point = points.get(index);
      builder.append("{\"x\":").append(point.get("x")).append(",\"y\":").append(point.get("y")).append("}");
    }
    return builder.append("]").toString();
  }

  private JsonNode postForm(String path, String body) throws IOException, InterruptedException {
    HttpRequest request =
        HttpRequest.newBuilder(URI.create(BASE_URL + path))
            .timeout(REQUEST_TIMEOUT)
            .header("User-Agent", USER_AGENT)
            .header("Referer", REFERER)
            .header("Origin", "https://beian.miit.gov.cn")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8))
            .build();
    return readJson(request);
  }

  private JsonNode postJson(String path, String token, String body)
      throws IOException, InterruptedException {
    HttpRequest.Builder builder = baseBuilder(path).header("Token", token);
    builder.POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8));
    return readJson(builder.build());
  }

  private JsonNode postQuery(String path, String sign, String uuid, String token, String body)
      throws IOException, InterruptedException {
    HttpRequest.Builder builder =
        baseBuilder(path).header("Sign", sign).header("Uuid", uuid).header("Token", token);
    builder.POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8));
    return readJson(builder.build());
  }

  private HttpRequest.Builder baseBuilder(String path) {
    return HttpRequest.newBuilder(URI.create(BASE_URL + path))
        .timeout(REQUEST_TIMEOUT)
        .header("User-Agent", USER_AGENT)
        .header("Referer", REFERER)
        .header("Origin", "https://beian.miit.gov.cn")
        .header("Content-Type", "application/json")
        .header("Cookie", "__jsluid_s=" + shortUuid());
  }

  private JsonNode readJson(HttpRequest request) throws IOException, InterruptedException {
    HttpResponse<String> response =
        client.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
    if (response.statusCode() / 100 != 2) {
      throw new MiitException("MIIT 返回 HTTP " + response.statusCode());
    }
    if (response.body() == null || response.body().isBlank()) {
      throw new MiitException("MIIT 返回空响应");
    }
    return json.readTree(response.body());
  }

  private static String shortUuid() {
    return UUID.randomUUID().toString().replace("-", "").substring(0, 32);
  }

  enum Kind {
    SUCCESS,
    CAPTCHA_REQUIRED,
    FAILED
  }

  record Challenge(String uuid, String secretKey, String bigImage, String smallImage, String clientUid) {}

  record PendingCaptcha(
      String token, String uuid, String secretKey, String clientUid, String bigImage, String smallImage) {}

  static final class MiitResult {
    final Kind kind;
    final String reason;
    final List<IcpRecord> records;
    final int total;

    MiitResult(Kind kind, String reason, List<IcpRecord> records, int total) {
      this.kind = kind;
      this.reason = reason;
      this.records = records;
      this.total = total;
    }

    boolean success() {
      return kind == Kind.SUCCESS;
    }

    boolean wasBlockedByCaptcha() {
      return kind == Kind.CAPTCHA_REQUIRED;
    }

    static MiitResult success(List<IcpRecord> records, int total) {
      return new MiitResult(Kind.SUCCESS, "", records, total);
    }

    static MiitResult captchaRequired(String reason) {
      return new MiitResult(Kind.CAPTCHA_REQUIRED, reason, List.of(), 0);
    }

    static MiitResult failure(String reason) {
      return new MiitResult(Kind.FAILED, reason, List.of(), 0);
    }
  }

  static final class MiitException extends RuntimeException {
    MiitException(String message) {
      super(message);
    }

    MiitException(String message, Throwable cause) {
      super(message, cause);
    }
  }

  static final class MiitCaptchaRequiredException extends RuntimeException {
    MiitCaptchaRequiredException(String message) {
      super(message);
    }
  }
}