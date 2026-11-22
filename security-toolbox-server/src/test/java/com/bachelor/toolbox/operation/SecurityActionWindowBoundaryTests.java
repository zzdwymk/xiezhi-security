package com.bachelor.toolbox.operation;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.bachelor.toolbox.common.ApiException;
import java.time.Instant;
import org.junit.jupiter.api.Test;

/**
 * 第304轮：安全处置动作的执行时间窗边界。
 *
 * <p>原实现用 {@code now.isAfter(windowEnd)}，恰好在窗口结束时刻仍被判为"在窗内"，于是可以启动一个
 * 已经到期的处置动作。与 R303 的项目授权边界同源：结束时刻即应视为过期。
 */
class SecurityActionWindowBoundaryTests {
  private SecurityActionService service() {
    return new SecurityActionService(null, null, null, null, null);
  }

  private SecurityAction actionEndingAt(Instant end) {
    SecurityAction action = new SecurityAction();
    action.setWindowStart(end.minusSeconds(3600));
    action.setWindowEnd(end);
    return action;
  }

  @Test
  void exactlyAtWindowEndIsRejected() {
    Instant end = Instant.parse("2026-06-01T12:00:00Z");
    assertThatThrownBy(() -> service().ensureInsideExecutionWindow(actionEndingAt(end), end))
        .as("窗口结束时刻必须视为已结束，不能再启动处置动作")
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("不在批准执行时间窗内");
  }

  @Test
  void oneSecondBeforeWindowEndIsAllowed() {
    Instant end = Instant.parse("2026-06-01T12:00:00Z");
    assertThatCode(() -> service().ensureInsideExecutionWindow(actionEndingAt(end), end.minusSeconds(1)))
        .doesNotThrowAnyException();
  }
}
