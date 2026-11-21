package com.bachelor.toolbox.traffic;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import org.junit.jupiter.api.Test;

/** Round 275：代理自动动作去重键必须随会话结束释放，不能在长跑进程里无界增长。 */
class TrafficProxyAutoActionsRetentionTests {

  @Test
  void prunesOnlyTheStoppedSessionsKeys() {
    Set<String> actions = ConcurrentHashMap.newKeySet();
    actions.add("7:http_headers");
    actions.add("7:tls_config");
    actions.add("8:http_headers");

    TrafficProxyService.pruneSessionAutoActions(actions, 7L);

    assertThat(actions).containsExactly("8:http_headers");
  }

  @Test
  void repeatedStartStopCyclesDoNotAccumulateKeys() {
    Set<String> actions = ConcurrentHashMap.newKeySet();
    for (long sessionId = 1; sessionId <= 500; sessionId++) {
      actions.add(sessionId + ":http_headers");
      actions.add(sessionId + ":tls_config");
      TrafficProxyService.pruneSessionAutoActions(actions, sessionId);
    }
    assertThat(actions).isEmpty();
  }

  @Test
  void toleratesNullSessionIdAndEmptySet() {
    Set<String> actions = ConcurrentHashMap.newKeySet();
    actions.add("1:http_headers");
    TrafficProxyService.pruneSessionAutoActions(actions, null);
    assertThat(actions).containsExactly("1:http_headers");
    TrafficProxyService.pruneSessionAutoActions(Set.of(), 1L);
  }
}
