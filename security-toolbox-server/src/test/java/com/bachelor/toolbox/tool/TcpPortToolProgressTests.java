package com.bachelor.toolbox.tool;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.PortRangeParser;
import com.bachelor.toolbox.target.TargetPolicyService;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import org.junit.jupiter.api.Test;

/**
 * {@code tcp_ports} 的进度文本约束。
 *
 * <h2>针对的历史故障（task 1293）</h2>
 *
 * <p>授权端口为全段 {@code 1-65535} 时，工具把 65,535 个端口号整串拼进 {@code observer.operation()}
 * 的文本（382KB）。该文本被直接写进 {@code progress_message}（列宽 500），保存进度时抛
 * {@code Value too long}，异常冒到任务失败处理，整个任务在开始的瞬间就结束——界面上看到的是
 * 「一开始就超时」，真实原因（字段超长）被完全掩盖。
 *
 * <p>因此进度文本必须始终是供人阅读的摘要，长度与端口数量无关。这里不真正扫描：用会被授权校验
 * 拒绝的参数在扫描开始前就停住，只断言已上报的文本。
 */
class TcpPortToolProgressTests {
  /** 与 {@code SecurityTask#progressMessage} 的列宽一致。 */
  private static final int PROGRESS_MESSAGE_MAX_LENGTH = 500;

  private TcpPortTool tool() {
    TargetPolicyService policy = mock(TargetPolicyService.class);
    // 本机回环：连接要么立即成功，要么立即被拒，全段探测也在亚秒级完成。
    when(policy.validatedHost(any())).thenReturn("127.0.0.1");
    return new TcpPortTool(policy, new PortRangeParser(), 1, 65535, 200);
  }

  private AuthorizedTarget target(String allowedPorts) {
    AuthorizedTarget target = new AuthorizedTarget();
    target.setId(7L);
    target.setTargetValue("127.0.0.1");
    target.setAllowedPorts(allowedPorts);
    return target;
  }

  @Test
  void fullRangeProgressIsASummaryNotA382KBPortList() {
    CapturingObserver observer = new CapturingObserver();
    tool().execute(target("1-65535"), Map.of("ports", "1-65535"), observer);

    assertThat(observer.operations).isNotEmpty();
    String operation = observer.operations.get(0);
    assertThat(operation)
        .contains("TCP_CONNECT", "host=127.0.0.1", "count=65535")
        .doesNotContain("ports=1,2,3,4,5,6");
    assertThat(operation.length())
        .as("进度文本必须远小于 progress_message 的列宽")
        .isLessThanOrEqualTo(PROGRESS_MESSAGE_MAX_LENGTH);
  }

  @Test
  void explicitPortRangeIsShownAsTypedSoTheApprovalCanBeMatched() {
    CapturingObserver observer = new CapturingObserver();
    tool().execute(target("80,443,8000-8010"), Map.of("ports", "80,443,8000-8010"), observer);

    assertThat(observer.operations).isNotEmpty();
    assertThat(observer.operations.get(0))
        .contains("ports=80,443,8000-8010", "count=13");
  }

  private static final class CapturingObserver implements ToolExecutionObserver {
    final CopyOnWriteArrayList<String> operations = new CopyOnWriteArrayList<>();

    @Override
    public void operation(String operation) {
      if (operation != null) operations.add(operation);
    }
  }
}
