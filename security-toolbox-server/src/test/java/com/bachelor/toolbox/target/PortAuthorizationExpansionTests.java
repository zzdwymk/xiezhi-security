package com.bachelor.toolbox.target;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.bachelor.toolbox.ai.guard.EndpointParameterPolicy;
import com.bachelor.toolbox.common.ApiException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * 第373轮：授权端口校验不得把{@code allowedPorts}展开成集合。
 *
 * <p>{@code 1-65535} 是平台合法且被 {@code canonicalizeCompact} 刻意保留为紧凑串的授权范围，
 * 但授权校验处仍调用 {@code parse(...)} 把它展开成 65,535 个 Integer。这类校验在每条链接、
 * 每次探测、每次登记、每次任务创建都会执行，构成「全端口 × 请求数」的分配放大。
 *
 * <p>本测试通过记录 {@code parse} 的入参来**确定性地**证明是否发生展开（不依赖计时）：
 * 只要校验过程把目标授权串交给 {@code parse}，就视为展开。
 */
@DisplayName("授权端口校验不得展开 allowedPorts（第373轮）")
class PortAuthorizationExpansionTests {

  /** 记录 parse 调用入参的解析器：containsPort 保持真实实现。 */
  private static final class RecordingParser extends PortRangeParser {
    private final List<String> parseCalls = new ArrayList<>();

    @Override
    public java.util.Set<Integer> parse(String specification) {
      parseCalls.add(specification);
      return super.parse(specification);
    }

    @Override
    public java.util.Set<Integer> parse(String specification, int maxPorts) {
      parseCalls.add(specification);
      return super.parse(specification, maxPorts);
    }
  }

  private static AuthorizedTarget target(String allowedPorts) {
    AuthorizedTarget target = new AuthorizedTarget();
    target.setId(373L);
    target.setTargetValue("http://192.168.222.155/");
    target.setTargetType("URL");
    target.setAllowedPorts(allowedPorts);
    target.setEnabled(true);
    return target;
  }

  @Test
  @DisplayName("TargetPolicyService 不得把 1-65535 交给 parse 展开")
  void targetPolicyDoesNotExpandFullRange() {
    RecordingParser parser = new RecordingParser();
    TargetPolicyService policy = new TargetPolicyService(false, parser);

    assertThatCode(() -> policy.validateAuthorizedPort(target("1-65535"), 80))
        .doesNotThrowAnyException();

    assertThat(parser.parseCalls)
        .as("授权校验把 allowedPorts 交给了 parse(%s)，即发生了展开", parser.parseCalls)
        .noneMatch("1-65535"::equals);
  }

  @Test
  @DisplayName("EndpointParameterPolicy 的端口子集校验不得展开 allowedPorts")
  void endpointPolicyDoesNotExpandAuthorizedRange() {
    RecordingParser parser = new RecordingParser();
    EndpointParameterPolicy policy = new EndpointParameterPolicy(parser, 65535);
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("toolCode", "tcp_ports");
    body.put("parameters", Map.of("ports", "80,443"));

    policy.validateTaskCreationBody(target("1-65535"), body);

    assertThat(parser.parseCalls)
        .as("端口子集校验把 allowedPorts 交给了 parse(%s)，即发生了展开", parser.parseCalls)
        .noneMatch("1-65535"::equals);
    assertThat(parser.parseCalls).as("请求端口仍需受限额约束地解析").contains("80,443");
  }

  @Test
  @DisplayName("语义不变：越界端口仍被拒绝、边界端口仍被接受")
  void membershipSemanticsArePreserved() {
    TargetPolicyService policy = new TargetPolicyService(false, new PortRangeParser());
    assertThatCode(() -> policy.validateAuthorizedPort(target("80,443"), 443))
        .doesNotThrowAnyException();
    assertThatThrownBy(() -> policy.validateAuthorizedPort(target("80,443"), 8080))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("不在授权端口范围内");
    assertThatCode(() -> policy.validateAuthorizedPort(target("1-65535"), 65535))
        .doesNotThrowAnyException();
    assertThatThrownBy(() -> policy.validateAuthorizedPort(target("1-65535"), 0))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("必须在 1-65535 范围内");
  }

  @Test
  @DisplayName("非规范存量授权串仍然 fail-closed（不被静默放行）")
  void malformedAuthorizedPortsStillFailClosed() {
    TargetPolicyService policy = new TargetPolicyService(false, new PortRangeParser());
    for (String malformed : List.of("80,bad", "bad,80", "80,,443", "80,0", "0-65536")) {
      assertThatThrownBy(() -> policy.validateAuthorizedPort(target(malformed), 80))
          .as("非规范授权串 %s 必须拒绝", malformed)
          .isInstanceOf(ApiException.class);
    }
  }
}
