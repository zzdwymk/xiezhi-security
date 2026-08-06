package com.bachelor.toolbox.traffic;

import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.common.ApiException;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class TrafficReplayService {
  private static final Logger LOGGER = LoggerFactory.getLogger(TrafficReplayService.class);
  private static final int MAX_HEADERS = 64 * 1024;
  private static final int MAX_REQUEST_BODY = 1024 * 1024;
  private static final int MAX_RESPONSE_BODY = 4 * 1024 * 1024;
  private static final Pattern METHOD = Pattern.compile("[!#$%&'*+.^_`|~0-9A-Za-z-]{1,32}");
  private static final Pattern HEADER_NAME = Pattern.compile("[!#$%&'*+.^_`|~0-9A-Za-z-]+");
  private static final Pattern REQUEST_LINE =
      Pattern.compile(
          "[!#$%&'*+.^_`|~0-9A-Za-z-]+\\s+\\S+\\s+HTTP/(?:1\\.[01]|2)", Pattern.CASE_INSENSITIVE);
  private static final Set<String> SKIPPED_HEADERS =
      Set.of(
          "content-length",
          "connection",
          "proxy-connection",
          "proxy-authorization",
          "keep-alive",
          "expect",
          "te",
          "trailer");

  private final TrafficPacketRepository packets;
  private final AuditService audit;

  @Autowired
  public TrafficReplayService(TrafficPacketRepository packets, AuditService audit) {
    this.packets = packets;
    this.audit = audit;
  }

  public ReplayResponse replay(Long packetId, ReplayRequest request) {
    TrafficPacket source =
        packets.findById(packetId).orElseThrow(() -> new ApiException("流量记录不存在"));
    if (source.getTargetId() != null
        && source.getTargetId() > 0
        && !source.getTargetId().equals(request.targetId())) {
      throw new ApiException("已绑定授权目标的流量不允许切换到其他目标发送");
    }
    URI uri = validateUri(request.url(), source.getHost());
    String method = validateMethod(request.method());
    byte[] body =
        request.body() == null ? new byte[0] : request.body().getBytes(StandardCharsets.UTF_8);
    if (body.length > MAX_REQUEST_BODY) throw new ApiException("发包请求体不能超过 1 MB");
    int port = effectivePort(uri);
    String authorizedHost = uri.getHost();
    String auditDetail =
        "replayOnly,method=" + method + ",host=" + authorizedHost + ",port=" + port;
    long started = System.nanoTime();
    try {
      InetAddress address = InetAddress.getAllByName(authorizedHost)[0];
      List<HeaderLine> headers = parseHeaders(request.headers(), uri);
      ReplayResponse response = exchange(packetId, method, uri, address, headers, body, started);
      audit.record(
          "REPLAY_TRAFFIC_PACKET",
          "TRAFFIC_PACKET",
          packetId,
          auditDetail + ",status=" + response.statusCode(),
          "SUCCESS");
      return response;
    } catch (ApiException ex) {
      audit.record("REPLAY_TRAFFIC_PACKET", "TRAFFIC_PACKET", packetId, auditDetail, "REJECTED");
      throw ex;
    } catch (SocketTimeoutException ex) {
      audit.record("REPLAY_TRAFFIC_PACKET", "TRAFFIC_PACKET", packetId, auditDetail, "TIMEOUT");
      throw new ApiException("发包超时，目标在 30 秒内未完成响应");
    } catch (Exception ex) {
      audit.record("REPLAY_TRAFFIC_PACKET", "TRAFFIC_PACKET", packetId, auditDetail, "FAILED");
      LOGGER.warn("流量发包失败，流量={}，目标={}:{}", packetId, authorizedHost, port, ex);
      throw new ApiException("发包失败，请检查目标连接与服务日志");
    }
  }

  private ReplayResponse exchange(
      Long packetId,
      String method,
      URI uri,
      InetAddress address,
      List<HeaderLine> headers,
      byte[] body,
      long started)
      throws Exception {
    int port = effectivePort(uri);
    try (Socket tcp = new Socket()) {
      tcp.connect(new InetSocketAddress(address, port), 5_000);
      tcp.setSoTimeout(30_000);
      if ("https".equalsIgnoreCase(uri.getScheme())) {
        try (SSLSocket tls =
            (SSLSocket)
                SSLContext.getDefault()
                    .getSocketFactory()
                    .createSocket(tcp, uri.getHost(), port, true)) {
          tls.setSoTimeout(30_000);
          SSLParameters parameters = tls.getSSLParameters();
          parameters.setEndpointIdentificationAlgorithm("HTTPS");
          parameters.setApplicationProtocols(new String[] {"http/1.1"});
          tls.setSSLParameters(parameters);
          tls.startHandshake();
          String protocol = tls.getApplicationProtocol();
          if (!protocol.isEmpty() && !"http/1.1".equals(protocol)) {
            throw new IOException("目标未提供 HTTP/1.1");
          }
          return exchangeOnSocket(packetId, method, uri, tls, headers, body, started);
        }
      }
      return exchangeOnSocket(packetId, method, uri, tcp, headers, body, started);
    }
  }

  private ReplayResponse exchangeOnSocket(
      Long packetId,
      String method,
      URI uri,
      Socket socket,
      List<HeaderLine> headers,
      byte[] body,
      long started)
      throws Exception {
    OutputStream output = socket.getOutputStream();
    String requestHeaders = buildRequestHeaders(method, uri, headers, body.length);
    output.write(requestHeaders.getBytes(StandardCharsets.ISO_8859_1));
    output.write(body);
    output.flush();

    ResponseHead response = readFinalResponseHead(socket.getInputStream());
    BodyResult bodyResult =
        hasNoResponseBody(method, response.statusCode)
            ? new BodyResult(new byte[0], 0, false)
            : readResponseBody(socket.getInputStream(), response);
    boolean text =
        isTextContent(response.contentType) && isIdentityEncoding(response.contentEncoding);
    String responseBody =
        text
            ? new String(bodyResult.bytes, StandardCharsets.UTF_8)
            : Base64.getEncoder().encodeToString(bodyResult.bytes);
    return new ReplayResponse(
        packetId,
        "HTTP/1.1",
        method,
        uri.toString(),
        response.statusCode,
        response.reasonPhrase,
        response.rawHeaders,
        responseBody,
        text ? "TEXT" : "BASE64",
        response.contentType,
        bodyResult.responseBytes,
        Duration.ofNanos(System.nanoTime() - started).toMillis(),
        bodyResult.truncated);
  }

  private URI validateUri(String value, String sourceHost) {
    if (value == null || value.isBlank() || value.length() > 4096)
      throw new ApiException("发包 URL 无效或过长");
    try {
      URI uri = URI.create(value.trim());
      if (!"http".equalsIgnoreCase(uri.getScheme()) && !"https".equalsIgnoreCase(uri.getScheme())) {
        throw new ApiException("发包仅支持 HTTP 和 HTTPS");
      }
      if (uri.getHost() == null || uri.getHost().isBlank()) throw new ApiException("发包 URL 缺少主机名");
      if (uri.getRawUserInfo() != null) throw new ApiException("发包 URL 不允许包含账号或密码");
      if (uri.getRawFragment() != null) throw new ApiException("发包 URL 不允许包含 fragment");
      String normalized = normalizeHost(uri.getHost());
      if (sourceHost != null
          && !sourceHost.isBlank()
          && !normalized.equals(normalizeHost(sourceHost))) {
        throw new ApiException("发包 URL 主机必须与源流量及授权目标一致");
      }
      // Replay is intentionally independent from authorization targets.
      return uri;
    } catch (ApiException ex) {
      throw ex;
    } catch (Exception ex) {
      throw new ApiException("发包 URL 格式不正确");
    }
  }

  private String validateMethod(String value) {
    String method = value == null ? "" : value.trim().toUpperCase(Locale.ROOT);
    if (!METHOD.matcher(method).matches()) throw new ApiException("HTTP 方法无效");
    if (Set.of("CONNECT", "TRACE").contains(method)) throw new ApiException("发包器不允许使用 " + method);
    return method;
  }

  private List<HeaderLine> parseHeaders(String rawHeaders, URI uri) {
    String raw = rawHeaders == null ? "" : rawHeaders;
    if (raw.getBytes(StandardCharsets.UTF_8).length > MAX_HEADERS)
      throw new ApiException("发包请求头不能超过 64 KB");
    List<HeaderLine> result = new ArrayList<>();
    boolean firstContentLine = true;
    for (String line : raw.split("\\r?\\n", -1)) {
      if (line.isBlank()) continue;
      if (firstContentLine && REQUEST_LINE.matcher(line.trim()).matches()) {
        firstContentLine = false;
        continue;
      }
      firstContentLine = false;
      if (Character.isWhitespace(line.charAt(0))) throw new ApiException("发包请求头不允许折行");
      int separator = line.indexOf(':');
      if (separator <= 0) throw new ApiException("请求头必须使用 Name: Value 格式");
      String name = line.substring(0, separator).trim();
      String value = line.substring(separator + 1).trim();
      if (!HEADER_NAME.matcher(name).matches()) throw new ApiException("请求头名称无效: " + name);
      validateHeaderValue(value);
      String lower = name.toLowerCase(Locale.ROOT);
      if ("host".equals(lower)) {
        validateHostHeader(value, uri);
        continue;
      }
      if ("transfer-encoding".equals(lower) || "upgrade".equals(lower)) {
        throw new ApiException("发包器不支持请求头 " + name);
      }
      if (lower.startsWith(":")) throw new ApiException("发包器不接受 HTTP/2 伪首部");
      if (SKIPPED_HEADERS.contains(lower)) continue;
      result.add(new HeaderLine(name, value));
    }
    return result;
  }

  private void validateHeaderValue(String value) {
    for (int i = 0; i < value.length(); i++) {
      char character = value.charAt(i);
      if (character == '\t') continue;
      if (character < 0x20 || character == 0x7f || character > 0xff) {
        throw new ApiException("请求头值包含非法字符");
      }
    }
  }

  private void validateHostHeader(String value, URI uri) {
    HostPort supplied = parseHostPort(value, effectivePort(uri));
    if (!normalizeHost(supplied.host).equals(normalizeHost(uri.getHost()))
        || supplied.port != effectivePort(uri)) {
      throw new ApiException("Host 请求头必须与发包 URL 一致");
    }
  }

  private String buildRequestHeaders(
      String method, URI uri, List<HeaderLine> headers, int bodyLength) {
    String path = uri.getRawPath() == null || uri.getRawPath().isBlank() ? "/" : uri.getRawPath();
    if (uri.getRawQuery() != null) path += "?" + uri.getRawQuery();
    int port = effectivePort(uri);
    boolean defaultPort = "https".equalsIgnoreCase(uri.getScheme()) ? port == 443 : port == 80;
    String host = uri.getHost().contains(":") ? "[" + uri.getHost() + "]" : uri.getHost();
    StringBuilder request =
        new StringBuilder(method)
            .append(' ')
            .append(path)
            .append(" HTTP/1.1\r\nHost: ")
            .append(host)
            .append(defaultPort ? "" : ":" + port)
            .append("\r\n");
    boolean userAgent = false;
    for (HeaderLine header : headers) {
      request.append(header.name).append(": ").append(header.value).append("\r\n");
      if ("user-agent".equalsIgnoreCase(header.name)) userAgent = true;
    }
    if (!userAgent) request.append("User-Agent: Xiezhi-Repeater/0.2\r\n");
    if (bodyLength > 0 || Set.of("POST", "PUT", "PATCH").contains(method)) {
      request.append("Content-Length: ").append(bodyLength).append("\r\n");
    }
    return request.append("Connection: close\r\n\r\n").toString();
  }

  private ResponseHead readFinalResponseHead(InputStream input) throws IOException {
    while (true) {
      byte[] raw = readHeader(input);
      if (raw.length == 0) throw new IOException("目标未返回 HTTP 响应");
      String text = new String(raw, StandardCharsets.ISO_8859_1);
      String[] lines = text.split("\r\n");
      String[] statusParts = lines[0].split(" ", 3);
      if (statusParts.length < 2) throw new IOException("目标 HTTP 状态行无效");
      int status;
      try {
        status = Integer.parseInt(statusParts[1]);
      } catch (NumberFormatException ex) {
        throw new IOException("目标 HTTP 状态码无效");
      }
      if (status >= 100 && status < 200 && status != 101) continue;
      if (status == 101) throw new IOException("发包器不支持 Upgrade/WebSocket 响应");
      String transferEncoding = headerValue(lines, "Transfer-Encoding");
      boolean chunked =
          transferEncoding != null && transferEncoding.toLowerCase(Locale.ROOT).contains("chunked");
      Long contentLength =
          chunked ? null : parseResponseContentLength(headerValue(lines, "Content-Length"));
      return new ResponseHead(
          status,
          statusParts.length == 3 ? statusParts[2] : "",
          text,
          headerValue(lines, "Content-Type"),
          headerValue(lines, "Content-Encoding"),
          contentLength,
          chunked);
    }
  }

  private BodyResult readResponseBody(InputStream input, ResponseHead response) throws IOException {
    LimitedBody body = new LimitedBody();
    if (response.chunked) {
      while (!body.truncated) {
        String line = readLine(input, 8192);
        int semicolon = line.indexOf(';');
        String sizeText = (semicolon < 0 ? line : line.substring(0, semicolon)).trim();
        long size;
        try {
          size = Long.parseLong(sizeText, 16);
        } catch (NumberFormatException ex) {
          throw new IOException("目标分块响应长度无效");
        }
        if (size == 0) {
          while (!readLine(input, MAX_HEADERS).isEmpty()) {}
          break;
        }
        readFixed(input, size, body);
        if (!body.truncated) expectCrlf(input);
      }
    } else if (response.contentLength != null) {
      readFixed(input, response.contentLength, body);
      if (response.contentLength > MAX_RESPONSE_BODY) body.responseBytes = response.contentLength;
    } else {
      byte[] buffer = new byte[8192];
      int read;
      while (!body.truncated && (read = input.read(buffer)) != -1) body.append(buffer, read);
    }
    return body.result();
  }

  private void readFixed(InputStream input, long length, LimitedBody body) throws IOException {
    byte[] buffer = new byte[8192];
    long remaining = length;
    while (remaining > 0 && !body.truncated) {
      int read = input.read(buffer, 0, (int) Math.min(buffer.length, remaining));
      if (read < 0) throw new EOFException("目标响应体提前结束");
      body.append(buffer, read);
      remaining -= read;
    }
  }

  private byte[] readHeader(InputStream input) throws IOException {
    ByteArrayOutputStream bytes = new ByteArrayOutputStream();
    int state = 0;
    int value;
    while ((value = input.read()) != -1) {
      bytes.write(value);
      state =
          state == 0 && value == '\r'
              ? 1
              : state == 1 && value == '\n'
                  ? 2
                  : state == 2 && value == '\r' ? 3 : state == 3 && value == '\n' ? 4 : 0;
      if (state == 4) return bytes.toByteArray();
      if (bytes.size() > MAX_HEADERS) throw new IOException("目标响应头超过 64 KB");
    }
    if (bytes.size() > 0) throw new EOFException("目标 HTTP 响应头不完整");
    return new byte[0];
  }

  private String readLine(InputStream input, int maxLength) throws IOException {
    ByteArrayOutputStream bytes = new ByteArrayOutputStream();
    int previous = -1;
    int value;
    while ((value = input.read()) != -1) {
      if (previous == '\r' && value == '\n') {
        byte[] line = bytes.toByteArray();
        return new String(line, 0, Math.max(0, line.length - 1), StandardCharsets.ISO_8859_1);
      }
      bytes.write(value);
      previous = value;
      if (bytes.size() > maxLength) throw new IOException("目标响应行超过限制");
    }
    throw new EOFException("目标响应提前结束");
  }

  private void expectCrlf(InputStream input) throws IOException {
    if (input.read() != '\r' || input.read() != '\n') throw new IOException("目标分块响应格式错误");
  }

  private String headerValue(String[] lines, String name) {
    for (String line : lines) {
      int separator = line.indexOf(':');
      if (separator > 0 && line.substring(0, separator).trim().equalsIgnoreCase(name)) {
        return line.substring(separator + 1).trim();
      }
    }
    return null;
  }

  private Long parseResponseContentLength(String value) throws IOException {
    if (value == null) return null;
    try {
      long parsed = Long.parseLong(value);
      if (parsed < 0) throw new NumberFormatException();
      return parsed;
    } catch (NumberFormatException ex) {
      throw new IOException("目标 Content-Length 无效");
    }
  }

  private int effectivePort(URI uri) {
    return uri.getPort() > 0 ? uri.getPort() : "https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80;
  }

  private boolean hasNoResponseBody(String method, int status) {
    return "HEAD".equals(method) || status >= 100 && status < 200 || status == 204 || status == 304;
  }

  private boolean isTextContent(String contentType) {
    if (contentType == null) return false;
    String value = contentType.toLowerCase(Locale.ROOT);
    return value.startsWith("text/")
        || value.contains("json")
        || value.contains("xml")
        || value.contains("html")
        || value.contains("javascript")
        || value.contains("form-urlencoded");
  }

  private boolean isIdentityEncoding(String contentEncoding) {
    return contentEncoding == null
        || contentEncoding.isBlank()
        || "identity".equalsIgnoreCase(contentEncoding);
  }

  private String normalizeHost(String host) {
    return host.toLowerCase(Locale.ROOT).replaceAll("\\.$", "");
  }

  private HostPort parseHostPort(String value, int fallback) {
    String host = value.trim();
    if (host.startsWith("[")) {
      int close = host.indexOf(']');
      if (close < 1) throw new ApiException("Host 请求头无效");
      return new HostPort(
          host.substring(1, close),
          close + 1 < host.length() && host.charAt(close + 1) == ':'
              ? parsePort(host.substring(close + 2))
              : fallback);
    }
    int colon = host.lastIndexOf(':');
    if (colon > 0 && host.indexOf(':') == colon)
      return new HostPort(host.substring(0, colon), parsePort(host.substring(colon + 1)));
    return new HostPort(host, fallback);
  }

  private int parsePort(String value) {
    try {
      int port = Integer.parseInt(value);
      if (port < 1 || port > 65535) throw new NumberFormatException();
      return port;
    } catch (NumberFormatException ex) {
      throw new ApiException("Host 请求头端口无效");
    }
  }

  public record ReplayRequest(
      Long targetId,
      @NotBlank(message = "HTTP 方法不能为空") @Size(max = 32, message = "HTTP 方法不能超过 32 个字符")
          String method,
      @NotBlank(message = "发包 URL 不能为空") @Size(max = 4096, message = "发包 URL 不能超过 4096 个字符")
          String url,
      @Size(max = MAX_HEADERS, message = "发包请求头不能超过 64 KB") String headers,
      @Size(max = MAX_REQUEST_BODY, message = "发包请求体不能超过 1 MB") String body) {}

  public record ReplayResponse(
      Long sourcePacketId,
      String protocol,
      String method,
      String url,
      int statusCode,
      String reasonPhrase,
      String responseHeaders,
      String responseBody,
      String bodyEncoding,
      String contentType,
      long responseBytes,
      long durationMs,
      boolean truncated) {}

  private record HeaderLine(String name, String value) {}

  private record HostPort(String host, int port) {}

  private record ResponseHead(
      int statusCode,
      String reasonPhrase,
      String rawHeaders,
      String contentType,
      String contentEncoding,
      Long contentLength,
      boolean chunked) {}

  private record BodyResult(byte[] bytes, long responseBytes, boolean truncated) {}

  private static final class LimitedBody {
    private final ByteArrayOutputStream output = new ByteArrayOutputStream();
    private long responseBytes;
    private boolean truncated;

    private void append(byte[] bytes, int length) {
      responseBytes += length;
      int available = MAX_RESPONSE_BODY - output.size();
      if (available > 0) output.write(bytes, 0, Math.min(available, length));
      if (length > available) truncated = true;
    }

    private BodyResult result() {
      return new BodyResult(output.toByteArray(), responseBytes, truncated);
    }
  }
}
