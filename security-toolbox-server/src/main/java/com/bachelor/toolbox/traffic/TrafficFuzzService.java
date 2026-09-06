package com.bachelor.toolbox.traffic;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.traffic.TrafficReplayService.ReplayRequest;
import com.bachelor.toolbox.traffic.TrafficReplayService.ReplayResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import org.springframework.stereotype.Service;

/**
 * Loop-based parameter fuzzing against an authorized HTTP target. The request (method/URL/headers
 * or body) may contain a {@code §name§} placeholder; each payload is substituted in turn and the
 * request is replayed through {@link TrafficReplayService}, then every response is compared to a
 * baseline (placeholder := empty) to surface likely reflections or anomalies.
 *
 * <p>This self-contained loop does not depend on any external fuzz engine's REST contract; the ZAP
 * bridge, when available, is layered on top elsewhere. A baseline request always runs first so all
 * payloads can be diffed for response changes.
 */
@Service
public class TrafficFuzzService {
  private static final String MARKER = "\u00a7name\u00a7"; // §name§
  private static final int MAX_PAYLOADS = 200;
  private static final int MAX_PAYLOAD_LENGTH = 4 * 1024;
  private static final int MAX_DISPLAY_PAYLOAD = 48;

  private final TrafficReplayService replay;

  public TrafficFuzzService(TrafficReplayService replay) {
    this.replay = replay;
  }

  public FuzzResponse fuzz(Long packetId, FuzzRequest request) {
    if (request == null) {
      throw new ApiException("fuzz 请求不能为空");
    }
    String url = request.url() == null ? "" : request.url();
    String body = request.body() == null ? "" : request.body();
    String headers = request.headers() == null ? "" : request.headers();
    if (!url.contains(MARKER) && !body.contains(MARKER) && !headers.contains(MARKER)) {
      throw new ApiException("请求中未发现要模糊的占位符 " + MARKER);
    }
    List<String> payloads = normalizePayloads(request.payloads());

    ReplayResponse baseline = run(packetId, request, url, body, headers, "");
    String baselineDigest = digestOf(baseline);

    List<FuzzHit> results = new ArrayList<>();
    results.add(
        new FuzzHit(
            "<<baseline>>",
            baseline.statusCode(),
            baseline.reasonPhrase() == null ? "" : baseline.reasonPhrase(),
            baseline.durationMs(),
            baseline.responseBytes(),
            baselineDigest.substring(0, Math.min(8, baselineDigest.length())),
            baseline.statusCode(),
            false));

    for (String payload : payloads) {
      ReplayResponse result = run(packetId, request, url, body, headers, payload);
      String digest = digestOf(result);
      boolean changed = !statusAndLen(result).equals(statusAndLen(baseline))
          || !digest.equals(baselineDigest);
      results.add(
          new FuzzHit(
              abbreviate(payload),
              result.statusCode(),
              result.reasonPhrase() == null ? "" : result.reasonPhrase(),
              result.durationMs(),
              result.responseBytes(),
              digest.substring(0, Math.min(8, digest.length())),
              result.statusCode(),
              changed));
    }
    return new FuzzResponse(packetId, request.method(), url, results, payloads.size());
  }

  private ReplayResponse run(
      Long packetId,
      FuzzRequest request,
      String url,
      String body,
      String headers,
      String payload) {
    ReplayRequest nested =
        new ReplayRequest(
            request.targetId(),
            request.method(),
            url.replace(MARKER, payload),
            headers.replace(MARKER, payload),
            body.replace(MARKER, payload));
    return replay.replay(packetId, nested);
  }

  private List<String> normalizePayloads(List<String> payloads) {
    List<String> result = new ArrayList<>();
    if (payloads == null) {
      return result;
    }
    for (String payload : payloads) {
      if (payload == null || payload.isBlank()) {
        continue;
      }
      String value = payload.length() > MAX_PAYLOAD_LENGTH ? payload.substring(0, MAX_PAYLOAD_LENGTH) : payload;
      result.add(value);
      if (result.size() >= MAX_PAYLOADS) {
        break;
      }
    }
    return result;
  }

  private String abbreviate(String value) {
    if (value == null) {
      return "";
    }
    return value.length() > MAX_DISPLAY_PAYLOAD ? value.substring(0, MAX_DISPLAY_PAYLOAD) : value;
  }

  private String digestOf(ReplayResponse response) {
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      byte[] bytes =
          (response.statusCode() + "|" + response.responseBody())
              .getBytes(StandardCharsets.UTF_8);
      return hex(digest.digest(bytes));
    } catch (Exception ex) {
      return String.valueOf(response.statusCode());
    }
  }

  private String statusAndLen(ReplayResponse response) {
    return response.statusCode() + ":" + response.responseBody().length();
  }

  private String hex(byte[] bytes) {
    StringBuilder builder = new StringBuilder(bytes.length * 2);
    for (byte b : bytes) {
      builder.append(String.format("%02x", b));
    }
    return builder.toString();
  }

  public record FuzzRequest(
      Long targetId,
      String method,
      String url,
      String headers,
      String body,
      List<String> payloads) {}

  public record FuzzHit(
      String payload,
      Integer statusCode,
      String reason,
      long durationMs,
      long responseBytes,
      String digestPrefix,
      Integer effectiveStatus,
      boolean changed) {}

  public record FuzzResponse(
      Long packetId,
      String method,
      String url,
      List<FuzzHit> results,
      int payloadCount) {}
}