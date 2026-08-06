package com.bachelor.toolbox.traffic;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.TargetPolicyService;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

final class LocalTrafficProxy implements AutoCloseable {
  static final String CLIENT_ERROR_MESSAGE = "代理请求处理失败，请稍后重试";

  private static final Logger LOGGER = LoggerFactory.getLogger(LocalTrafficProxy.class);
  private static final int MAX_HEADERS = 64 * 1024;
  private static final int MAX_REQUEST_BODY = 1024 * 1024;
  private static final int MAX_PREVIEW = 64 * 1024;
  private static final Set<String> SUPPORTED_VERSIONS = Set.of("HTTP/1.0", "HTTP/1.1");

  private final AuthorizedTarget target;
  private final TargetPolicyService policy;
  private final MitmCertificateAuthority certificateAuthority;
  private final Consumer<Capture> capture;
  private final ExecutorService workers = Executors.newCachedThreadPool();
  private volatile boolean running;
  private ServerSocket server;
  private int listenPort;

  LocalTrafficProxy(
      AuthorizedTarget target,
      TargetPolicyService policy,
      MitmCertificateAuthority certificateAuthority,
      Consumer<Capture> capture) {
    this.target = target;
    this.policy = policy;
    this.certificateAuthority = certificateAuthority;
    this.capture = capture;
  }

  void start(int port) throws IOException {
    listenPort = port;
    server = new ServerSocket();
    server.setReuseAddress(true);
    server.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), port));
    running = true;
    workers.submit(
        () -> {
          while (running) {
            try {
              Socket client = server.accept();
              workers.submit(() -> handle(client));
            } catch (IOException ignored) {
              // Closing the listening socket is how stop() wakes accept().
            }
          }
        });
  }

  private void handle(Socket client) {
    long started = System.nanoTime();
    boolean responseBecameTls = false;
    try {
      client.setSoTimeout(60_000);
      InputStream in = client.getInputStream();
      OutputStream out = client.getOutputStream();
      byte[] headerBytes = readHeader(in);
      if (headerBytes.length == 0) return;
      String rawHeader = new String(headerBytes, StandardCharsets.ISO_8859_1);
      String[] lines = headerLines(rawHeader);
      String[] requestLine = parseRequestLine(lines);
      String method = requestLine[0].toUpperCase(Locale.ROOT);
      if ("CONNECT".equals(method)) {
        responseBecameTls = handleConnect(client, in, out, requestLine[1], rawHeader, started);
      } else {
        handleHttp(in, out, method, requestLine[1], requestLine[2], lines, rawHeader, started);
      }
    } catch (Exception ex) {
      LOGGER.warn("本地流量代理处理请求失败", ex);
      if (!responseBecameTls) {
        try {
          writeError(client.getOutputStream(), statusFor(ex));
        } catch (Exception ignored) {
        }
      }
    } finally {
      try {
        client.close();
      } catch (IOException ignored) {
      }
    }
  }

  /**
   * @return true once a 200 CONNECT response has been sent and the client side must be treated as
   *     TLS.
   */
  private boolean handleConnect(
      Socket client,
      InputStream clientIn,
      OutputStream clientOut,
      String authority,
      String rawHeader,
      long started)
      throws Exception {
    HostPort hp = parseAuthority(authority, 443);
    InetAddress address = authorize(hp.host(), hp.port());
    if (!certificateAuthority.enabled()) {
      tunnelConnect(clientIn, clientOut, hp, address, rawHeader, started);
      return true;
    }

    SSLSocket upstreamTls;
    try {
      upstreamTls = openUpstreamTls(address, hp.host(), hp.port());
    } catch (Exception ex) {
      capture.accept(
          new Capture(
              "CONNECT",
              "CONNECT",
              "https",
              hp.host(),
              hp.port(),
              null,
              null,
              rawHeader,
              "",
              "",
              "",
              0,
              0,
              elapsed(started),
              "TLS_UPSTREAM_FAILED",
              null,
              CLIENT_ERROR_MESSAGE));
      throw ex;
    }

    boolean tunnelEstablished = false;
    try (upstreamTls) {
      clientOut.write(
          "HTTP/1.1 200 Connection Established\r\nProxy-Agent: Xiezhi\r\n\r\n"
              .getBytes(StandardCharsets.ISO_8859_1));
      clientOut.flush();
      tunnelEstablished = true;

      SSLSocket clientTls;
      try {
        clientTls = openClientTls(client, hp.host(), hp.port());
        clientTls.startHandshake();
      } catch (Exception ex) {
        LOGGER.warn("客户端 TLS 握手失败，目标={}:{}", hp.host(), hp.port(), ex);
        capture.accept(
            new Capture(
                "CONNECT",
                "CONNECT",
                "https",
                hp.host(),
                hp.port(),
                null,
                null,
                rawHeader,
                "",
                "",
                "",
                0,
                0,
                elapsed(started),
                "TLS_CLIENT_REJECTED",
                null,
                CLIENT_ERROR_MESSAGE));
        return true;
      }

      try (clientTls) {
        if ("h2".equals(clientTls.getApplicationProtocol())) {
          AtomicBoolean firstUpstreamAvailable = new AtomicBoolean(true);
          new Http2MitmConnection(
                  clientTls.getInputStream(),
                  clientTls.getOutputStream(),
                  hp,
                  () ->
                      firstUpstreamAvailable.compareAndSet(true, false)
                          ? upstreamTls
                          : openUpstreamTls(address, hp.host(), hp.port()),
                  capture)
              .run();
        } else {
          handleDecryptedHttps(
              clientTls.getInputStream(), clientTls.getOutputStream(), upstreamTls, hp, started);
        }
      }
      return true;
    } catch (Exception ex) {
      // CONNECT 成功后写入明文错误响应会破坏 TLS 流，此时仅记录服务端日志并关闭连接。
      if (tunnelEstablished) {
        LOGGER.warn("CONNECT 隧道处理失败，目标={}:{}", hp.host(), hp.port(), ex);
        return true;
      }
      throw ex;
    }
  }

  private void handleDecryptedHttps(
      InputStream clientIn,
      OutputStream clientOut,
      SSLSocket upstreamTls,
      HostPort connectTarget,
      long started) {
    String rawHeader = "";
    String method = "CONNECT";
    String path = null;
    byte[] body = new byte[0];
    try {
      byte[] headerBytes = readHeader(clientIn);
      if (headerBytes.length == 0) return;
      rawHeader = new String(headerBytes, StandardCharsets.ISO_8859_1);
      String[] lines = headerLines(rawHeader);
      String[] requestLine = parseRequestLine(lines);
      method = requestLine[0].toUpperCase(Locale.ROOT);
      path = normalizeHttpsPath(requestLine[1]);
      String version = requestLine[2];
      if (!SUPPORTED_VERSIONS.contains(version)) {
        throw new ProxyHttpException(505, "HTTPS 抓包目前仅支持 HTTP/1.0 和 HTTP/1.1");
      }
      validateHttpsAuthority(lines, connectTarget);
      rejectUnsupportedRequest(lines);
      int contentLength = parseContentLength(lines);
      if (contentLength > MAX_REQUEST_BODY) {
        throw new ProxyHttpException(413, "代理请求体超过 1 MB 限制");
      }
      body = readFixedBody(clientIn, contentLength);

      String forwardedHeaders = rewriteHeaders(lines, method, path, version);
      ExchangeResult result = forwardExchange(upstreamTls, clientOut, forwardedHeaders, body);
      capture.accept(
          new Capture(
              "HTTPS",
              method,
              "https",
              connectTarget.host(),
              connectTarget.port(),
              path,
              result.statusCode(),
              rawHeader,
              previewRequestBody(body, headerValue(lines, "Content-Type")),
              result.responseHeaders(),
              result.responseBody(),
              body.length,
              result.responseBytes(),
              elapsed(started),
              result.truncated() ? "DECRYPTED_TRUNCATED" : "DECRYPTED",
              result.contentType(),
              null));
    } catch (Exception ex) {
      int status = statusFor(ex);
      LOGGER.warn("HTTPS MITM 请求处理失败，目标={}:{}", connectTarget.host(), connectTarget.port(), ex);
      try {
        writeError(clientOut, status);
      } catch (Exception ignored) {
      }
      capture.accept(
          new Capture(
              "HTTPS",
              method,
              "https",
              connectTarget.host(),
              connectTarget.port(),
              path,
              null,
              rawHeader,
              previewRequestBody(body, null),
              "",
              "",
              body.length,
              0,
              elapsed(started),
              ex instanceof ProxyHttpException ? "UNSUPPORTED" : "DECRYPT_FAILED",
              null,
              CLIENT_ERROR_MESSAGE));
    }
  }

  private ExchangeResult forwardExchange(
      SSLSocket upstreamTls, OutputStream clientOut, String forwardedHeaders, byte[] body)
      throws Exception {
    OutputStream upstreamOut = upstreamTls.getOutputStream();
    upstreamOut.write(forwardedHeaders.getBytes(StandardCharsets.ISO_8859_1));
    upstreamOut.write(body);
    upstreamOut.flush();

    InputStream upstreamIn = upstreamTls.getInputStream();
    byte[] responseHeaderBytes = readHeader(upstreamIn);
    if (responseHeaderBytes.length == 0) throw new IOException("上游 HTTPS 服务未返回响应");
    String responseHeader = new String(responseHeaderBytes, StandardCharsets.ISO_8859_1);
    String[] responseLines = headerLines(responseHeader);
    Integer status = parseStatus(responseHeader);
    String contentType = headerValue(responseLines, "Content-Type");
    clientOut.write(responseHeaderBytes);

    long responseBytes = 0;
    ByteArrayOutputStream preview = new ByteArrayOutputStream();
    byte[] buffer = new byte[8192];
    int read;
    while ((read = upstreamIn.read(buffer)) != -1) {
      clientOut.write(buffer, 0, read);
      responseBytes += read;
      if (preview.size() < MAX_PREVIEW) {
        preview.write(buffer, 0, Math.min(read, MAX_PREVIEW - preview.size()));
      }
    }
    clientOut.flush();
    String responseBody =
        isTextContent(contentType) ? preview.toString(StandardCharsets.UTF_8) : "";
    return new ExchangeResult(
        status,
        responseHeader,
        responseBody,
        contentType,
        responseBytes,
        responseBytes > MAX_PREVIEW);
  }

  private SSLSocket openUpstreamTls(InetAddress address, String host, int port) throws Exception {
    Socket tcp = new Socket();
    try {
      tcp.connect(new InetSocketAddress(address, port), 5_000);
      tcp.setSoTimeout(30_000);
      SSLSocketFactory factory = SSLContext.getDefault().getSocketFactory();
      SSLSocket tls = (SSLSocket) factory.createSocket(tcp, host, port, true);
      SSLParameters parameters = tls.getSSLParameters();
      parameters.setEndpointIdentificationAlgorithm("HTTPS");
      parameters.setApplicationProtocols(new String[] {"http/1.1"});
      tls.setSSLParameters(parameters);
      tls.startHandshake();
      if (!"http/1.1".equals(tls.getApplicationProtocol())
          && !tls.getApplicationProtocol().isEmpty()) {
        tls.close();
        throw new IOException("上游服务未提供 HTTP/1.1");
      }
      return tls;
    } catch (Exception ex) {
      try {
        tcp.close();
      } catch (IOException ignored) {
      }
      throw ex;
    }
  }

  private SSLSocket openClientTls(Socket client, String host, int port) throws Exception {
    SSLContext context = certificateAuthority.serverContext(host);
    SSLSocket tls = (SSLSocket) context.getSocketFactory().createSocket(client, host, port, false);
    tls.setUseClientMode(false);
    tls.setNeedClientAuth(false);
    tls.setSoTimeout(60_000);
    SSLParameters parameters = tls.getSSLParameters();
    parameters.setApplicationProtocols(new String[] {"h2", "http/1.1"});
    tls.setSSLParameters(parameters);
    return tls;
  }

  private void tunnelConnect(
      InputStream clientIn,
      OutputStream clientOut,
      HostPort hp,
      InetAddress address,
      String rawHeader,
      long started)
      throws Exception {
    AtomicLong up = new AtomicLong();
    AtomicLong down = new AtomicLong();
    try (Socket upstream = new Socket()) {
      upstream.connect(new InetSocketAddress(address, hp.port()), 5_000);
      upstream.setSoTimeout(60_000);
      clientOut.write(
          "HTTP/1.1 200 Connection Established\r\nConnection: close\r\n\r\n"
              .getBytes(StandardCharsets.ISO_8859_1));
      clientOut.flush();
      Future<?> a = workers.submit(() -> copy(clientIn, upstream, up));
      Future<?> b =
          workers.submit(
              () -> {
                try {
                  copy(upstream.getInputStream(), clientOut, down);
                } catch (Exception ignored) {
                }
              });
      try {
        a.get(65, TimeUnit.SECONDS);
      } catch (Exception ignored) {
      }
      try {
        upstream.close();
      } catch (Exception ignored) {
      }
      try {
        b.get(5, TimeUnit.SECONDS);
      } catch (Exception ignored) {
      }
    } finally {
      capture.accept(
          new Capture(
              "CONNECT",
              "CONNECT",
              "https",
              hp.host(),
              hp.port(),
              null,
              200,
              rawHeader,
              "",
              "",
              "",
              up.get(),
              down.get(),
              elapsed(started),
              "METADATA_ONLY",
              null,
              null));
    }
  }

  private void handleHttp(
      InputStream clientIn,
      OutputStream clientOut,
      String method,
      String requestTarget,
      String version,
      String[] lines,
      String rawHeader,
      long started)
      throws Exception {
    if (!SUPPORTED_VERSIONS.contains(version))
      throw new ProxyHttpException(505, "仅支持 HTTP/1.0 和 HTTP/1.1");
    rejectUnsupportedRequest(lines);
    URI uri = requestTarget.contains("://") ? URI.create(requestTarget) : null;
    String host = uri != null ? uri.getHost() : hostOnly(headerValue(lines, "Host"));
    if (host == null) throw new ApiException("代理请求缺少 Host");
    int port =
        uri != null && uri.getPort() > 0
            ? uri.getPort()
            : portFromHostHeader(
                headerValue(lines, "Host"),
                uri != null && "https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80);
    String scheme = uri == null ? "http" : uri.getScheme();
    String path = uri == null ? requestTarget : pathAndQuery(uri);
    InetAddress address = authorize(host, port);
    int contentLength = parseContentLength(lines);
    if (contentLength > MAX_REQUEST_BODY) throw new ProxyHttpException(413, "代理请求体超过 1 MB 限制");
    byte[] body = readFixedBody(clientIn, contentLength);
    String forwardedHeaders = rewriteHeaders(lines, method, path, version);

    long responseBytes = 0;
    Integer status;
    String responseHeader;
    String responsePreview;
    String contentType;
    try (Socket upstream = new Socket()) {
      upstream.connect(new InetSocketAddress(address, port), 5_000);
      upstream.setSoTimeout(30_000);
      OutputStream upstreamOut = upstream.getOutputStream();
      upstreamOut.write(forwardedHeaders.getBytes(StandardCharsets.ISO_8859_1));
      upstreamOut.write(body);
      upstreamOut.flush();
      InputStream upstreamIn = upstream.getInputStream();
      byte[] responseHeaderBytes = readHeader(upstreamIn);
      responseHeader = new String(responseHeaderBytes, StandardCharsets.ISO_8859_1);
      status = parseStatus(responseHeader);
      contentType = headerValue(headerLines(responseHeader), "Content-Type");
      clientOut.write(responseHeaderBytes);
      ByteArrayOutputStream preview = new ByteArrayOutputStream();
      byte[] buffer = new byte[8192];
      int read;
      while ((read = upstreamIn.read(buffer)) != -1) {
        clientOut.write(buffer, 0, read);
        responseBytes += read;
        if (preview.size() < MAX_PREVIEW) {
          preview.write(buffer, 0, Math.min(read, MAX_PREVIEW - preview.size()));
        }
      }
      clientOut.flush();
      responsePreview = isTextContent(contentType) ? preview.toString(StandardCharsets.UTF_8) : "";
    }
    capture.accept(
        new Capture(
            "HTTP",
            method,
            scheme,
            host,
            port,
            path,
            status,
            rawHeader,
            previewRequestBody(body, headerValue(lines, "Content-Type")),
            responseHeader,
            responsePreview,
            body.length,
            responseBytes,
            elapsed(started),
            responseBytes > MAX_PREVIEW ? "TRUNCATED" : "CAPTURED",
            contentType,
            null));
  }

  private InetAddress authorize(String requestHost, int port) throws Exception {
    if (requestHost == null || requestHost.isBlank() || port < 1 || port > 65535) {
      throw new ApiException("代理目标地址或端口无效");
    }
    String normalized = normalizeHost(requestHost);
    if (target != null) {
      String expected = targetHost();
      if (!normalized.equals(normalizeHost(expected))) throw new ApiException("代理仅允许访问当前授权目标");
      policy.validatedHost(target);
      policy.validateAuthorizedPort(target, port);
      return InetAddress.getAllByName(expected)[0];
    }
    InetAddress address = InetAddress.getAllByName(normalized)[0];
    if (address.isLoopbackAddress() && port == listenPort)
      throw new ApiException("不允许将代理请求转发回代理自身");
    return address;
  }

  private void validateHttpsAuthority(String[] lines, HostPort connectTarget) {
    String hostHeader = headerValue(lines, "Host");
    if (hostHeader == null || hostHeader.isBlank())
      throw new ProxyHttpException(400, "HTTPS 请求缺少 Host");
    String requestHost = hostOnly(hostHeader);
    int requestPort = portFromHostHeader(hostHeader, 443);
    if (!normalizeHost(requestHost).equals(normalizeHost(connectTarget.host()))
        || requestPort != connectTarget.port()) {
      throw new ProxyHttpException(403, "HTTPS 请求 Host 必须与 CONNECT 目标一致");
    }
  }

  private void rejectUnsupportedRequest(String[] lines) {
    String transferEncoding = headerValue(lines, "Transfer-Encoding");
    if (transferEncoding != null
        && !transferEncoding.isBlank()
        && !"identity".equalsIgnoreCase(transferEncoding)) {
      throw new ProxyHttpException(501, "抓包代理暂不支持分块请求体");
    }
    if (headerValue(lines, "Upgrade") != null
        || headerTokens(lines, "Connection").contains("upgrade")) {
      throw new ProxyHttpException(501, "抓包代理暂不支持 WebSocket/Upgrade");
    }
  }

  private String targetHost() {
    URI uri =
        URI.create(
            target.getTargetValue().contains("://")
                ? target.getTargetValue()
                : "//" + target.getTargetValue());
    if (uri.getHost() == null) throw new ApiException("授权目标地址无效");
    return uri.getHost();
  }

  private byte[] readHeader(InputStream in) throws IOException {
    ByteArrayOutputStream bytes = new ByteArrayOutputStream();
    int state = 0;
    int value;
    while ((value = in.read()) != -1) {
      bytes.write(value);
      state =
          (state == 0 && value == '\r')
              ? 1
              : (state == 1 && value == '\n')
                  ? 2
                  : (state == 2 && value == '\r') ? 3 : (state == 3 && value == '\n') ? 4 : 0;
      if (state == 4) break;
      if (bytes.size() > MAX_HEADERS) throw new IOException("请求头超过 64 KB");
    }
    if (bytes.size() > 0 && state != 4) throw new IOException("HTTP 请求头不完整");
    return bytes.toByteArray();
  }

  private String rewriteHeaders(String[] lines, String method, String path, String version) {
    StringBuilder b =
        new StringBuilder(method)
            .append(' ')
            .append(path)
            .append(' ')
            .append(version)
            .append("\r\n");
    for (int i = 1; i < lines.length; i++) {
      String line = lines[i];
      String lower = line.toLowerCase(Locale.ROOT);
      if (lower.startsWith("proxy-connection:")
          || lower.startsWith("proxy-authorization:")
          || lower.startsWith("connection:")
          || lower.startsWith("keep-alive:")
          || lower.startsWith("transfer-encoding:")
          || line.isBlank()) continue;
      b.append(line).append("\r\n");
    }
    return b.append("Connection: close\r\n\r\n").toString();
  }

  private String[] parseRequestLine(String[] lines) {
    if (lines.length == 0) throw new ProxyHttpException(400, "代理请求行缺失");
    String[] requestLine = lines[0].split(" ", 3);
    if (requestLine.length != 3) throw new ProxyHttpException(400, "代理请求行格式错误");
    return requestLine;
  }

  private String[] headerLines(String rawHeader) {
    return rawHeader.split("\r\n");
  }

  private String headerValue(String[] lines, String name) {
    for (String line : lines) {
      int i = line.indexOf(':');
      if (i > 0 && line.substring(0, i).trim().equalsIgnoreCase(name))
        return line.substring(i + 1).trim();
    }
    return null;
  }

  private Set<String> headerTokens(String[] lines, String name) {
    String value = headerValue(lines, name);
    if (value == null) return Set.of();
    java.util.HashSet<String> result = new java.util.HashSet<>();
    for (String token : value.split(",")) result.add(token.trim().toLowerCase(Locale.ROOT));
    return result;
  }

  private int parseContentLength(String[] lines) {
    String value = headerValue(lines, "Content-Length");
    if (value == null) return 0;
    try {
      int length = Integer.parseInt(value);
      if (length < 0) throw new NumberFormatException();
      return length;
    } catch (Exception ex) {
      throw new ProxyHttpException(400, "Content-Length 无效");
    }
  }

  private byte[] readFixedBody(InputStream in, int length) throws IOException {
    byte[] body = in.readNBytes(length);
    if (body.length != length) throw new IOException("请求体提前结束");
    return body;
  }

  private int parseStatus(String headers) {
    try {
      return Integer.parseInt(headers.split("\r\n", 2)[0].split(" ")[1]);
    } catch (Exception ex) {
      return 0;
    }
  }

  private int portFromHostHeader(String header, int fallback) {
    if (header == null) return fallback;
    if (header.startsWith("[")) {
      int close = header.indexOf(']');
      if (close >= 0 && close + 1 < header.length() && header.charAt(close + 1) == ':') {
        return parsePort(header.substring(close + 2), fallback);
      }
      return fallback;
    }
    int index = header.lastIndexOf(':');
    return index > 0 && header.indexOf(':') == index
        ? parsePort(header.substring(index + 1), fallback)
        : fallback;
  }

  private int parsePort(String value, int fallback) {
    try {
      return Integer.parseInt(value);
    } catch (Exception ignored) {
      return fallback;
    }
  }

  private String hostOnly(String header) {
    if (header == null) return null;
    String value = header.trim();
    if (value.startsWith("[")) {
      int close = value.indexOf(']');
      return close > 0 ? value.substring(1, close) : value;
    }
    int index = value.lastIndexOf(':');
    return index > 0 && value.indexOf(':') == index ? value.substring(0, index) : value;
  }

  private HostPort parseAuthority(String value, int fallback) {
    String authority = value.trim();
    if (authority.startsWith("[")) {
      int close = authority.indexOf(']');
      if (close < 1) throw new ProxyHttpException(400, "CONNECT 目标格式错误");
      String host = authority.substring(1, close);
      int port =
          close + 1 < authority.length() && authority.charAt(close + 1) == ':'
              ? requiredPort(authority.substring(close + 2))
              : fallback;
      return new HostPort(host, port);
    }
    int index = authority.lastIndexOf(':');
    if (index < 1 || authority.indexOf(':') != index) return new HostPort(authority, fallback);
    return new HostPort(
        authority.substring(0, index), requiredPort(authority.substring(index + 1)));
  }

  private int requiredPort(String value) {
    try {
      int port = Integer.parseInt(value);
      if (port < 1 || port > 65535) throw new NumberFormatException();
      return port;
    } catch (Exception ex) {
      throw new ProxyHttpException(400, "CONNECT 目标端口无效");
    }
  }

  private String normalizeHttpsPath(String requestTarget) {
    if (requestTarget.contains("://")) {
      URI uri = URI.create(requestTarget);
      if (!"https".equalsIgnoreCase(uri.getScheme()))
        throw new ProxyHttpException(400, "CONNECT 内仅允许 HTTPS 请求");
      return pathAndQuery(uri);
    }
    if (!requestTarget.startsWith("/") && !"*".equals(requestTarget)) {
      throw new ProxyHttpException(400, "HTTPS 请求目标格式错误");
    }
    return requestTarget;
  }

  private String pathAndQuery(URI uri) {
    String path = uri.getRawPath() == null || uri.getRawPath().isBlank() ? "/" : uri.getRawPath();
    return path + (uri.getRawQuery() == null ? "" : "?" + uri.getRawQuery());
  }

  private String normalizeHost(String host) {
    return host.toLowerCase(Locale.ROOT).replaceAll("\\.$", "");
  }

  private String previewRequestBody(byte[] body, String contentType) {
    if (body.length == 0) return "";
    if (contentType != null
        && !isTextContent(contentType)
        && !contentType.toLowerCase(Locale.ROOT).contains("x-www-form-urlencoded")) return "";
    int length = Math.min(body.length, MAX_PREVIEW);
    return new String(body, 0, length, StandardCharsets.UTF_8);
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

  private void copy(InputStream in, Socket out, AtomicLong counter) {
    try {
      copy(in, out.getOutputStream(), counter);
    } catch (Exception ignored) {
    }
  }

  private void copy(InputStream in, OutputStream out, AtomicLong counter) {
    try {
      byte[] buffer = new byte[8192];
      int read;
      while ((read = in.read(buffer)) != -1) {
        out.write(buffer, 0, read);
        out.flush();
        counter.addAndGet(read);
      }
    } catch (Exception ignored) {
    }
  }

  private void writeError(OutputStream output, int status) throws IOException {
    byte[] body = CLIENT_ERROR_MESSAGE.getBytes(StandardCharsets.UTF_8);
    output.write(
        ("HTTP/1.1 "
                + status
                + " \r\nContent-Type: text/plain; charset=utf-8\r\n"
                + "Content-Length: "
                + body.length
                + "\r\nConnection: close\r\n\r\n")
            .getBytes(StandardCharsets.ISO_8859_1));
    output.write(body);
    output.flush();
  }

  private int statusFor(Exception ex) {
    if (ex instanceof ProxyHttpException proxyException) return proxyException.status;
    if (ex instanceof ApiException) return 403;
    return 502;
  }

  private long elapsed(long started) {
    return Duration.ofNanos(System.nanoTime() - started).toMillis();
  }

  @Override
  public void close() {
    running = false;
    try {
      if (server != null) server.close();
    } catch (Exception ignored) {
    }
    workers.shutdownNow();
  }

  record HostPort(String host, int port) {}

  record ExchangeResult(
      Integer statusCode,
      String responseHeaders,
      String responseBody,
      String contentType,
      long responseBytes,
      boolean truncated) {}

  record Capture(
      String protocol,
      String method,
      String scheme,
      String host,
      int port,
      String path,
      Integer statusCode,
      String requestHeaders,
      String requestBody,
      String responseHeaders,
      String responseBody,
      long requestBytes,
      long responseBytes,
      long durationMs,
      String captureState,
      String contentType,
      String errorMessage) {}

  private static final class ProxyHttpException extends RuntimeException {
    private final int status;

    private ProxyHttpException(int status, String message) {
      super(message);
      this.status = status;
    }
  }
}
