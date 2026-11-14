package com.bachelor.toolbox.tool.zap;

import java.time.Duration;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/** Supplies {@link ZapDaemon} instances from resolved configuration at scan time. */
@Component
public class ZapDaemonFactory implements ZapDaemonSupplier {
  private final String executable;
  private final String host;
  private final int port;
  private final Duration startupTimeout;
  private final int maxAlerts;

  public ZapDaemonFactory(
      @Value("${toolbox.execution.zap-path:zap}") String executable,
      @Value("${toolbox.execution.zap-host:127.0.0.1}") String host,
      @Value("${toolbox.execution.zap-port:8090}") int port,
      @Value("${toolbox.execution.zap-startup-seconds:120}") long startupSeconds,
      @Value("${toolbox.execution.zap-max-alerts:500}") int maxAlerts) {
    this.executable = executable;
    this.host = host;
    this.port = port;
    this.startupTimeout = Duration.ofSeconds(startupSeconds);
    this.maxAlerts = Math.max(1, maxAlerts);
  }

  public ZapDaemon create() {
    return new LocalZapDaemon(executable, host, port, startupTimeout, maxAlerts);
  }
}