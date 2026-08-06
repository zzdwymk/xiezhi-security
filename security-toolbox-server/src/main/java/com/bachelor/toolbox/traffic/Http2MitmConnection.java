package com.bachelor.toolbox.traffic;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.codec.http2.DefaultHttp2DataFrame;
import io.netty.handler.codec.http2.DefaultHttp2Headers;
import io.netty.handler.codec.http2.DefaultHttp2HeadersFrame;
import io.netty.handler.codec.http2.DefaultHttp2ResetFrame;
import io.netty.handler.codec.http2.Http2DataFrame;
import io.netty.handler.codec.http2.Http2Error;
import io.netty.handler.codec.http2.Http2Frame;
import io.netty.handler.codec.http2.Http2FrameCodecBuilder;
import io.netty.handler.codec.http2.Http2FrameStream;
import io.netty.handler.codec.http2.Http2GoAwayFrame;
import io.netty.handler.codec.http2.Http2Headers;
import io.netty.handler.codec.http2.Http2HeadersFrame;
import io.netty.handler.codec.http2.Http2ResetFrame;
import io.netty.handler.codec.http2.Http2Settings;
import io.netty.handler.codec.http2.Http2StreamFrame;
import io.netty.util.ReferenceCountUtil;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;
import javax.net.ssl.SSLSocket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Terminates browser-side HTTP/2 and forwards each authorized stream through a separately verified
 * upstream HTTP/1.1 TLS connection. Netty owns frame parsing, HPACK and HTTP/2 flow control; this
 * class owns request limits, authority validation, protocol translation and capture previews.
 */
final class Http2MitmConnection {
  private static final Logger LOGGER = LoggerFactory.getLogger(Http2MitmConnection.class);
  private static final int MAX_HEADERS = 64 * 1024;
  private static final int MAX_REQUEST_BODY = 1024 * 1024;
  private static final int MAX_PREVIEW = 64 * 1024;
  private static final int FRAME_DATA_SIZE = 16 * 1024;
  private static final Set<String> HOP_BY_HOP =
      Set.of("connection", "proxy-connection", "keep-alive", "transfer-encoding", "upgrade");

  private final InputStream clientIn;
  private final OutputStream clientOut;
  private final LocalTrafficProxy.HostPort connectTarget;
  private final UpstreamTlsFactory upstreamFactory;
  private final Consumer<LocalTrafficProxy.Capture> capture;
  private final Map<Integer, RequestState> requests = new HashMap<>();
  private final EmbeddedChannel codec;

  Http2MitmConnection(
      InputStream clientIn,
      OutputStream clientOut,
      LocalTrafficProxy.HostPort connectTarget,
      UpstreamTlsFactory upstreamFactory,
      Consumer<LocalTrafficProxy.Capture> capture) {
    this.clientIn = clientIn;
    this.clientOut = clientOut;
    this.connectTarget = connectTarget;
    this.upstreamFactory = upstreamFactory;
    this.capture = capture;
    Http2Settings settings =
        new Http2Settings()
            .maxConcurrentStreams(32L)
            .maxHeaderListSize((long) MAX_HEADERS)
            .initialWindowSize(MAX_REQUEST_BODY);
    this.codec =
        new EmbeddedChannel(
            Http2FrameCodecBuilder.forServer()
                .validateHeaders(true)
                .autoAckSettingsFrame(true)
                .autoAckPingFrame(true)
                .initialSettings(settings)
                .build());
  }

  void run() throws Exception {
    try {
      drainOutbound();
      byte[] buffer = new byte[16 * 1024];
      int read;
      while ((read = clientIn.read(buffer)) != -1) {
        ByteBuf input = Unpooled.copiedBuffer(buffer, 0, read);
        codec.writeInbound(input);
        codec.runPendingTasks();
        drainInbound();
        drainOutbound();
      }
    } finally {
      requests.clear();
      try {
        codec.finish();
        drainOutbound();
      } finally {
        codec.finishAndReleaseAll();
      }
    }
  }

  private void drainInbound() throws Exception {
    Object message;
    while ((message = codec.readInbound()) != null) {
      try {
        if (message instanceof Http2HeadersFrame headersFrame) {
          onHeaders(headersFrame);
        } else if (message instanceof Http2DataFrame dataFrame) {
          onData(dataFrame);
        } else if (message instanceof Http2ResetFrame resetFrame) {
          requests.remove(streamId(resetFrame));
        } else if (message instanceof Http2GoAwayFrame) {
          return;
        }
        // SETTINGS/PING/WINDOW_UPDATE are terminated by the codec. Automatic ACK output is
        // drained after this inbound batch and is never forwarded to an upstream connection.
      } finally {
        ReferenceCountUtil.release(message);
      }
    }
  }

  private void onHeaders(Http2HeadersFrame frame) throws Exception {
    int streamId = streamId(frame);
    RequestState state = requests.get(streamId);
    if (state != null) {
      state.reject(501, "HTTP/2 请求尾部字段暂不支持");
      if (frame.isEndStream()) finishRequest(state);
      return;
    }

    state = RequestState.from(frame.stream(), frame.headers());
    requests.put(streamId, state);
    try {
      validateInitialHeaders(state);
    } catch (RequestRejectedException ex) {
      state.reject(ex.status, ex.reason);
    }
    if (frame.isEndStream()) finishRequest(state);
  }

  private void onData(Http2DataFrame frame) throws Exception {
    RequestState state = requests.get(streamId(frame));
    if (state == null) {
      writeFrame(new DefaultHttp2ResetFrame(Http2Error.PROTOCOL_ERROR).stream(frame.stream()));
      return;
    }
    int readable = frame.content().readableBytes();
    state.requestBytes += readable;
    if (state.requestBytes > MAX_REQUEST_BODY) {
      state.reject(413, "HTTP/2 请求体超过 1 MB 限制");
    } else if (state.rejectedStatus == null) {
      byte[] bytes = new byte[readable];
      frame.content().getBytes(frame.content().readerIndex(), bytes);
      state.body.write(bytes);
    }
    if (frame.isEndStream()) finishRequest(state);
  }

  private void finishRequest(RequestState state) throws Exception {
    requests.remove(state.stream.id());
    if (state.rejectedStatus == null
        && state.declaredContentLength != null
        && state.declaredContentLength != state.requestBytes) {
      state.reject(400, "HTTP/2 Content-Length 与实际请求体长度不一致");
    }
    if (state.rejectedStatus != null) {
      sendError(state.stream, state.rejectedStatus);
      captureFailure(
          state, state.rejectedStatus == 403 ? "REJECTED" : "UNSUPPORTED", state.rejectedMessage);
      return;
    }
    forward(state);
  }

  private void validateInitialHeaders(RequestState state) {
    if (state.method == null || state.method.isBlank()) throw rejected(400, "HTTP/2 请求缺少 :method");
    if ("CONNECT".equalsIgnoreCase(state.method) || state.headers.contains(":protocol")) {
      throw rejected(501, "HTTP/2 CONNECT/WebSocket 暂不支持");
    }
    if (!"https".equalsIgnoreCase(state.scheme)) throw rejected(400, "CONNECT 内仅允许 HTTPS 请求");
    if (state.path == null || (!state.path.startsWith("/") && !"*".equals(state.path))) {
      throw rejected(400, "HTTP/2 请求缺少有效的 :path");
    }
    Authority authority = parseAuthority(state.authority, 443);
    if (!normalizeHost(authority.host).equals(normalizeHost(connectTarget.host()))
        || authority.port != connectTarget.port()) {
      throw rejected(403, "HTTP/2 :authority 必须与 CONNECT 目标一致");
    }
    if (state.headerBytes > MAX_HEADERS) throw rejected(431, "HTTP/2 请求头超过 64 KB");
    state.declaredContentLength = contentLength(state.headers);
    if (state.declaredContentLength != null && state.declaredContentLength > MAX_REQUEST_BODY) {
      throw rejected(413, "HTTP/2 请求体超过 1 MB 限制");
    }
    CharSequence te = state.headers.get("te");
    if (te != null && !"trailers".equalsIgnoreCase(te.toString().trim())) {
      throw rejected(400, "HTTP/2 TE 仅允许 trailers");
    }
    for (String name : HOP_BY_HOP) {
      if (state.headers.contains(name)) throw rejected(400, "HTTP/2 请求包含禁止的连接级首部: " + name);
    }
  }

  private void forward(RequestState state) throws Exception {
    ForwardProgress progress = new ForwardProgress();
    try (SSLSocket upstream = upstreamFactory.open()) {
      byte[] body = state.body.toByteArray();
      OutputStream output = upstream.getOutputStream();
      output.write(toHttp1Request(state, body.length).getBytes(StandardCharsets.ISO_8859_1));
      output.write(body);
      output.flush();

      ResponseHead response = readFinalResponseHead(upstream.getInputStream());
      if (response.status == 101) throw new IOException("上游 Upgrade 响应不能转换为 HTTP/2");
      boolean noBody = hasNoResponseBody(state.method, response.status);
      Http2Headers responseHeaders = toHttp2ResponseHeaders(response);
      writeFrame(new DefaultHttp2HeadersFrame(responseHeaders, noBody).stream(state.stream));
      progress.responseStarted = true;

      ResponseBodyCapture responseBody =
          noBody
              ? new ResponseBodyCapture(0, "", false)
              : relayResponseBody(upstream.getInputStream(), state.stream, response);
      capture.accept(
          new LocalTrafficProxy.Capture(
              "HTTP/2",
              state.method,
              "https",
              connectTarget.host(),
              connectTarget.port(),
              state.path,
              response.status,
              state.rawHeaders(),
              previewRequestBody(state.body.toByteArray(), state.contentType),
              response.rawHeaders,
              responseBody.preview,
              state.requestBytes,
              responseBody.bytes,
              elapsed(state.started),
              responseBody.truncated ? "DECRYPTED_TRUNCATED" : "DECRYPTED",
              response.contentType,
              null));
    } catch (Exception ex) {
      LOGGER.warn("HTTP/2 MITM 请求转发失败，目标={}:{}", connectTarget.host(), connectTarget.port(), ex);
      if (progress.responseStarted) {
        try {
          writeFrame(new DefaultHttp2ResetFrame(Http2Error.INTERNAL_ERROR).stream(state.stream));
        } catch (Exception ignored) {
        }
      } else {
        sendError(state.stream, 502);
      }
      captureFailure(state, "DECRYPT_FAILED", LocalTrafficProxy.CLIENT_ERROR_MESSAGE);
    }
  }

  private ResponseBodyCapture relayResponseBody(
      InputStream input, Http2FrameStream stream, ResponseHead response) throws Exception {
    ByteArrayOutputStream preview = new ByteArrayOutputStream();
    long total = 0;
    if (response.chunked) {
      while (true) {
        String line = readLine(input, 8192);
        int semicolon = line.indexOf(';');
        String sizeText = (semicolon < 0 ? line : line.substring(0, semicolon)).trim();
        long chunkSize;
        try {
          chunkSize = Long.parseLong(sizeText, 16);
        } catch (NumberFormatException ex) {
          throw new IOException("上游分块响应长度无效");
        }
        if (chunkSize < 0) throw new IOException("上游分块响应长度无效");
        if (chunkSize == 0) {
          while (!readLine(input, MAX_HEADERS).isEmpty()) {
            // Trailer fields are consumed but not promoted to response headers.
          }
          break;
        }
        total += relayFixed(input, stream, chunkSize, preview);
        expectCrlf(input);
      }
    } else if (response.contentLength != null) {
      total = relayFixed(input, stream, response.contentLength, preview);
    } else {
      byte[] buffer = new byte[FRAME_DATA_SIZE];
      int read;
      while ((read = input.read(buffer)) != -1) {
        emitData(stream, buffer, read, false);
        total += read;
        appendPreview(preview, buffer, read);
      }
    }
    emitData(stream, new byte[0], 0, true);
    String text =
        isTextContent(response.contentType) ? preview.toString(StandardCharsets.UTF_8) : "";
    return new ResponseBodyCapture(total, text, total > MAX_PREVIEW);
  }

  private long relayFixed(
      InputStream input, Http2FrameStream stream, long length, ByteArrayOutputStream preview)
      throws Exception {
    long remaining = length;
    long total = 0;
    byte[] buffer = new byte[FRAME_DATA_SIZE];
    while (remaining > 0) {
      int read = input.read(buffer, 0, (int) Math.min(buffer.length, remaining));
      if (read < 0) throw new EOFException("上游响应体提前结束");
      emitData(stream, buffer, read, false);
      appendPreview(preview, buffer, read);
      total += read;
      remaining -= read;
    }
    return total;
  }

  private void emitData(Http2FrameStream stream, byte[] bytes, int length, boolean endStream)
      throws Exception {
    ByteBuf content = length == 0 ? Unpooled.EMPTY_BUFFER : Unpooled.copiedBuffer(bytes, 0, length);
    writeFrame(new DefaultHttp2DataFrame(content, endStream).stream(stream));
  }

  private void appendPreview(ByteArrayOutputStream preview, byte[] bytes, int length) {
    if (preview.size() >= MAX_PREVIEW) return;
    preview.write(bytes, 0, Math.min(length, MAX_PREVIEW - preview.size()));
  }

  private ResponseHead readFinalResponseHead(InputStream input) throws Exception {
    while (true) {
      byte[] raw = readHeader(input);
      if (raw.length == 0) throw new IOException("上游 HTTPS 服务未返回响应");
      String text = new String(raw, StandardCharsets.ISO_8859_1);
      String[] lines = text.split("\r\n");
      int status = parseStatus(lines[0]);
      if (status >= 100 && status < 200 && status != 101) continue;
      String contentType = headerValue(lines, "Content-Type");
      String transferEncoding = headerValue(lines, "Transfer-Encoding");
      boolean chunked =
          transferEncoding != null && transferEncoding.toLowerCase(Locale.ROOT).contains("chunked");
      Long contentLength = chunked ? null : responseContentLength(lines);
      return new ResponseHead(status, text, lines, contentType, contentLength, chunked);
    }
  }

  private Http2Headers toHttp2ResponseHeaders(ResponseHead response) {
    Http2Headers result = new DefaultHttp2Headers(true).status(Integer.toString(response.status));
    Set<String> connectionTokens = commaTokens(headerValue(response.lines, "Connection"));
    for (int i = 1; i < response.lines.length; i++) {
      String line = response.lines[i];
      int separator = line.indexOf(':');
      if (separator <= 0) continue;
      String name = line.substring(0, separator).trim().toLowerCase(Locale.ROOT);
      if (HOP_BY_HOP.contains(name)
          || connectionTokens.contains(name)
          || "trailer".equals(name)
          || response.chunked && "content-length".equals(name)) continue;
      String value = line.substring(separator + 1).trim();
      result.add(name, value);
    }
    return result;
  }

  private String toHttp1Request(RequestState state, int bodyLength) {
    StringBuilder request =
        new StringBuilder(state.method)
            .append(' ')
            .append(state.path)
            .append(" HTTP/1.1\r\nHost: ")
            .append(state.authority)
            .append("\r\n");
    for (Map.Entry<CharSequence, CharSequence> header : state.headers) {
      String name = header.getKey().toString().toLowerCase(Locale.ROOT);
      if (name.startsWith(":")
          || "host".equals(name)
          || "content-length".equals(name)
          || "expect".equals(name)
          || "proxy-authorization".equals(name)
          || HOP_BY_HOP.contains(name)) continue;
      request.append(name).append(": ").append(header.getValue()).append("\r\n");
    }
    if (bodyLength > 0 || state.declaredContentLength != null) {
      request.append("Content-Length: ").append(bodyLength).append("\r\n");
    }
    return request.append("Connection: close\r\n\r\n").toString();
  }

  private void sendError(Http2FrameStream stream, int status) throws Exception {
    byte[] body = LocalTrafficProxy.CLIENT_ERROR_MESSAGE.getBytes(StandardCharsets.UTF_8);
    Http2Headers headers =
        new DefaultHttp2Headers(true)
            .status(Integer.toString(status))
            .set("content-type", "text/plain; charset=utf-8")
            .setInt("content-length", body.length);
    writeFrame(new DefaultHttp2HeadersFrame(headers, body.length == 0).stream(stream));
    if (body.length > 0) emitData(stream, body, body.length, true);
  }

  private void captureFailure(RequestState state, String captureState, String error) {
    byte[] body = state.body.toByteArray();
    capture.accept(
        new LocalTrafficProxy.Capture(
            "HTTP/2",
            state.method,
            "https",
            connectTarget.host(),
            connectTarget.port(),
            state.path,
            null,
            state.rawHeaders(),
            previewRequestBody(body, state.contentType),
            "",
            "",
            state.requestBytes,
            0,
            elapsed(state.started),
            captureState,
            null,
            error));
  }

  private void writeFrame(Http2StreamFrame frame) throws Exception {
    codec.writeOutbound(frame);
    codec.runPendingTasks();
    drainOutbound();
  }

  private void drainOutbound() throws Exception {
    Object message;
    while ((message = codec.readOutbound()) != null) {
      try {
        if (!(message instanceof ByteBuf bytes)) {
          throw new IOException("未知 HTTP/2 编码输出: " + message.getClass().getSimpleName());
        }
        bytes.readBytes(clientOut, bytes.readableBytes());
      } finally {
        ReferenceCountUtil.release(message);
      }
    }
    clientOut.flush();
  }

  private int streamId(Http2Frame frame) {
    if (!(frame instanceof Http2StreamFrame streamFrame) || streamFrame.stream() == null) return -1;
    return streamFrame.stream().id();
  }

  private Long contentLength(Http2Headers headers) {
    java.util.List<CharSequence> values = headers.getAll("content-length");
    if (values.isEmpty()) return null;
    Long expected = null;
    for (CharSequence value : values) {
      long parsed;
      try {
        parsed = Long.parseLong(value.toString());
      } catch (NumberFormatException ex) {
        throw rejected(400, "HTTP/2 Content-Length 无效");
      }
      if (parsed < 0 || expected != null && expected != parsed) {
        throw rejected(400, "HTTP/2 Content-Length 无效");
      }
      expected = parsed;
    }
    return expected;
  }

  private Long responseContentLength(String[] lines) throws IOException {
    String value = headerValue(lines, "Content-Length");
    if (value == null) return null;
    try {
      long parsed = Long.parseLong(value);
      if (parsed < 0) throw new NumberFormatException();
      return parsed;
    } catch (NumberFormatException ex) {
      throw new IOException("上游 Content-Length 无效");
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
      if (bytes.size() > MAX_HEADERS) throw new IOException("上游响应头超过 64 KB");
    }
    if (bytes.size() > 0) throw new EOFException("上游 HTTP 响应头不完整");
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
      if (bytes.size() > maxLength) throw new IOException("上游响应行超过限制");
    }
    throw new EOFException("上游响应提前结束");
  }

  private void expectCrlf(InputStream input) throws IOException {
    if (input.read() != '\r' || input.read() != '\n') throw new IOException("上游分块响应格式错误");
  }

  private int parseStatus(String statusLine) throws IOException {
    try {
      int status = Integer.parseInt(statusLine.split(" ")[1]);
      if (status < 100 || status > 999) throw new NumberFormatException();
      return status;
    } catch (Exception ex) {
      throw new IOException("上游 HTTP 响应状态行无效");
    }
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

  private Set<String> commaTokens(String value) {
    if (value == null) return Set.of();
    Set<String> tokens = new HashSet<>();
    for (String token : value.split(",")) tokens.add(token.trim().toLowerCase(Locale.ROOT));
    return tokens;
  }

  private boolean hasNoResponseBody(String method, int status) {
    return "HEAD".equalsIgnoreCase(method)
        || status >= 100 && status < 200
        || status == 204
        || status == 304;
  }

  private String previewRequestBody(byte[] body, String contentType) {
    if (body.length == 0) return "";
    if (contentType != null && !isTextContent(contentType)) return "";
    return new String(body, 0, Math.min(body.length, MAX_PREVIEW), StandardCharsets.UTF_8);
  }

  private boolean isTextContent(String contentType) {
    if (contentType == null) return false;
    String value = contentType.toLowerCase(Locale.ROOT);
    return value.contains("json")
        || value.startsWith("text/")
        || value.contains("xml")
        || value.contains("html")
        || value.contains("javascript")
        || value.contains("form-urlencoded");
  }

  private Authority parseAuthority(String value, int fallbackPort) {
    if (value == null || value.isBlank()) throw rejected(400, "HTTP/2 请求缺少 :authority");
    String authority = value.trim();
    if (authority.startsWith("[")) {
      int close = authority.indexOf(']');
      if (close < 1) throw rejected(400, "HTTP/2 :authority 无效");
      String host = authority.substring(1, close);
      int port =
          close + 1 < authority.length() && authority.charAt(close + 1) == ':'
              ? parseRequiredPort(authority.substring(close + 2))
              : fallbackPort;
      return new Authority(host, port);
    }
    int colon = authority.lastIndexOf(':');
    if (colon > 0 && authority.indexOf(':') == colon) {
      return new Authority(
          authority.substring(0, colon), parseRequiredPort(authority.substring(colon + 1)));
    }
    return new Authority(authority, fallbackPort);
  }

  private int parseRequiredPort(String value) {
    try {
      int port = Integer.parseInt(value);
      if (port < 1 || port > 65535) throw new NumberFormatException();
      return port;
    } catch (NumberFormatException ex) {
      throw rejected(400, "HTTP/2 :authority 端口无效");
    }
  }

  private String normalizeHost(String host) {
    return host.toLowerCase(Locale.ROOT).replaceAll("\\.$", "");
  }

  private RequestRejectedException rejected(int status, String message) {
    return new RequestRejectedException(status, message);
  }

  private long elapsed(long started) {
    return Duration.ofNanos(System.nanoTime() - started).toMillis();
  }

  @FunctionalInterface
  interface UpstreamTlsFactory {
    SSLSocket open() throws Exception;
  }

  private static final class RequestState {
    private final Http2FrameStream stream;
    private final Http2Headers headers;
    private final String method;
    private final String scheme;
    private final String authority;
    private final String path;
    private final String contentType;
    private final int headerBytes;
    private final long started = System.nanoTime();
    private final ByteArrayOutputStream body = new ByteArrayOutputStream();
    private long requestBytes;
    private Long declaredContentLength;
    private Integer rejectedStatus;
    private String rejectedMessage;

    private RequestState(Http2FrameStream stream, Http2Headers headers) {
      this.stream = stream;
      this.headers = headers;
      this.method = text(headers.method());
      this.scheme = text(headers.scheme());
      this.authority = text(headers.authority());
      this.path = text(headers.path());
      this.contentType = text(headers.get("content-type"));
      int size = 0;
      for (Map.Entry<CharSequence, CharSequence> header : headers) {
        size += header.getKey().length() + header.getValue().length() + 4;
      }
      this.headerBytes = size;
    }

    private static RequestState from(Http2FrameStream stream, Http2Headers headers) {
      return new RequestState(stream, headers);
    }

    private static String text(CharSequence value) {
      return value == null ? null : value.toString();
    }

    private void reject(int status, String message) {
      if (rejectedStatus == null) {
        rejectedStatus = status;
        rejectedMessage = message;
      }
    }

    private String rawHeaders() {
      StringBuilder raw =
          new StringBuilder(method == null ? "" : method)
              .append(' ')
              .append(path == null ? "" : path)
              .append(" HTTP/2\r\n");
      if (authority != null) raw.append("Host: ").append(authority).append("\r\n");
      for (Map.Entry<CharSequence, CharSequence> header : headers) {
        if (!header.getKey().toString().startsWith(":")) {
          raw.append(header.getKey()).append(": ").append(header.getValue()).append("\r\n");
        }
      }
      return raw.append("\r\n").toString();
    }
  }

  private static final class ForwardProgress {
    private boolean responseStarted;
  }

  private static final class RequestRejectedException extends RuntimeException {
    private final int status;
    private final String reason;

    private RequestRejectedException(int status, String reason) {
      super(reason);
      this.status = status;
      this.reason = reason;
    }
  }

  private record Authority(String host, int port) {}

  private record ResponseHead(
      int status,
      String rawHeaders,
      String[] lines,
      String contentType,
      Long contentLength,
      boolean chunked) {}

  private record ResponseBodyCapture(long bytes, String preview, boolean truncated) {}
}
