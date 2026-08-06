package com.bachelor.toolbox.tool;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.TargetPolicyService;
import java.net.URI;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import javax.net.ssl.*;
import org.springframework.stereotype.Component;

@Component
public class TlsConfigurationTool implements SecurityTool {
  private final TargetPolicyService policyService;

  public TlsConfigurationTool(TargetPolicyService policyService) {
    this.policyService = policyService;
  }

  @Override
  public String code() {
    return "tls_config";
  }

  @Override
  public String displayName() {
    return "TLS 基础配置检查";
  }

  @Override
  public String description() {
    return "读取授权 HTTPS 目标的协商协议、密码套件和证书有效期";
  }

  @Override
  public ToolExecutionResult execute(AuthorizedTarget target, Map<String, Object> parameters)
      throws Exception {
    return execute(target, parameters, ToolExecutionObserver.NOOP);
  }

  @Override
  public ToolExecutionResult execute(
      AuthorizedTarget target, Map<String, Object> parameters, ToolExecutionObserver observer)
      throws Exception {
    URI uri = policyService.validatedHttpUri(target);
    if (!"https".equalsIgnoreCase(uri.getScheme())) {
      throw new ApiException("TLS 检查要求目标使用 https://");
    }
    int port = uri.getPort() > 0 ? uri.getPort() : 443;
    observer.operation("TLS_HANDSHAKE host=" + uri.getHost() + " port=" + port + " timeout=8000ms");
    observer.progress(0, 3, "正在初始化 TLS 检查");
    SSLContext context = SSLContext.getInstance("TLS");
    context.init(
        null,
        new TrustManager[] {
          new X509TrustManager() {
            public void checkClientTrusted(X509Certificate[] chain, String authType) {}

            public void checkServerTrusted(X509Certificate[] chain, String authType) {}

            public X509Certificate[] getAcceptedIssuers() {
              return new X509Certificate[0];
            }
          }
        },
        new SecureRandom());
    observer.progress(1, 3, "TLS 上下文已就绪，正在握手");

    List<FindingDraft> findings = new ArrayList<>();
    try (SSLSocket socket =
        (SSLSocket) context.getSocketFactory().createSocket(uri.getHost(), port)) {
      socket.setSoTimeout(8000);
      socket.startHandshake();
      observer.progress(2, 3, "TLS 握手完成，正在分析证书和协议");
      SSLSession session = socket.getSession();
      X509Certificate certificate = (X509Certificate) session.getPeerCertificates()[0];
      long days = ChronoUnit.DAYS.between(Instant.now(), certificate.getNotAfter().toInstant());
      if (days < 30) {
        findings.add(
            new FindingDraft(
                "TLS 证书即将过期",
                days < 0 ? "HIGH" : "MEDIUM",
                "服务器证书剩余有效期为 " + days + " 天。",
                "notAfter=" + certificate.getNotAfter(),
                "及时更新证书并配置到期监控。"));
      }
      if ("TLSv1".equals(session.getProtocol()) || "TLSv1.1".equals(session.getProtocol())) {
        findings.add(
            new FindingDraft(
                "协商到过时 TLS 协议",
                "HIGH",
                "目标仍允许使用过时的 " + session.getProtocol() + "。",
                "protocol=" + session.getProtocol(),
                "禁用 TLS 1.0/1.1，优先启用 TLS 1.2 和 TLS 1.3。"));
      }
      observer.progress(3, 3, "TLS 配置检查完成");
      return new ToolExecutionResult(
          "TLS 握手成功，协议 " + session.getProtocol() + "，证书剩余 " + days + " 天",
          Map.of(
              "host", uri.getHost(),
              "port", port,
              "protocol", session.getProtocol(),
              "cipherSuite", session.getCipherSuite(),
              "subject", certificate.getSubjectX500Principal().getName(),
              "issuer", certificate.getIssuerX500Principal().getName(),
              "notAfter", certificate.getNotAfter().toInstant().toString()),
          findings);
    }
  }
}
