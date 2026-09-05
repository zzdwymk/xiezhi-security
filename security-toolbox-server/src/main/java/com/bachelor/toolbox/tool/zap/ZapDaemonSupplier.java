package com.bachelor.toolbox.tool.zap;

/** Supplies {@link ZapDaemon} instances so callers (and tests) control how ZAP is brought up. */
@FunctionalInterface
public interface ZapDaemonSupplier {
  ZapDaemon create();
}