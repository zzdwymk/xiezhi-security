package com.bachelor.toolbox.ai;

/** Public orchestration phases emitted by both synchronous and streaming agent APIs. */
public enum AgentPhase {
  SESSION,
  ENGAGEMENT,
  RECONNAISSANCE,
  MAPPING,
  DISCOVERY,
  VALIDATION,
  IMPACT,
  RETEST,
  REPORTING,
  PLANNER,
  AUTHORIZATION_GUARD,
  APPROVAL,
  EXECUTOR,
  REVIEWER,
  RETRY,
  COMPLETED,
  ERROR
}
