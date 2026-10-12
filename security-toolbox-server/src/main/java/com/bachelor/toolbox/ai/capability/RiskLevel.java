package com.bachelor.toolbox.ai.capability;

/**
 * 风险等级，用于风险分级与确认策略（设计文档 §6.6）。
 *
 * <p>等级按"影响面 × 可逆性"划分，而非按 HTTP 方法，目的是避免确认疲劳。
 */
public enum RiskLevel {
  /** 无副作用，自动放行。 */
  SAFE,
  /** 有副作用但通常可逆，需批量确认。 */
  SENSITIVE,
  /** 不可逆或触及授权边界，需逐次确认并强化审计。 */
  DESTRUCTIVE
}
