package com.bachelor.toolbox.tool;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.PortRangeParser;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * 第375轮：越界端口必须在任务创建期被拒绝，而不是创建成功、执行时失败。
 *
 * <p>修复前真实行为：{@code POST /api/tasks} 对越界端口返回 202，任务随后 FAILED
 * （「请求端口超出授权目标的允许端口范围」），留下失败任务记录并占用任务配额。
 */
@DisplayName("创建期端口子集校验（第375轮）")
class ToolPortScopeTests {
  private final PortRangeParser parser = new PortRangeParser();

  private static AuthorizedTarget target(String allowedPorts) {
    AuthorizedTarget target = new AuthorizedTarget();
    target.setId(375L);
    target.setTargetValue("http://192.168.222.155/");
    target.setAllowedPorts(allowedPorts);
    target.setEnabled(true);
    return target;
  }

  private static Map<String, Object> ports(Object value) {
    Map<String, Object> map = new LinkedHashMap<>();
    map.put("ports", value);
    return map;
  }

  @Test
  @DisplayName("范围内端口创建期放行")
  void inRangePortsAreAccepted() {
    assertThatCode(() -> ToolPortScope.requireWithinAuthorization(
        target("80,443"), "tcp_ports", ports("80,443"), parser, 1024)).doesNotThrowAnyException();
    assertThatCode(() -> ToolPortScope.requireWithinAuthorization(
        target("80-90"), "nmap_service_scan", ports("85"), parser, 1024)).doesNotThrowAnyException();
  }

  @Test
  @DisplayName("越界端口创建期即被拒绝（不再等到执行时失败）")
  void outOfRangePortsAreRejectedAtCreation() {
    assertThatThrownBy(() -> ToolPortScope.requireWithinAuthorization(
        target("80-90"), "tcp_ports", ports("443"), parser, 1024))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("超出目标授权范围");
    // 部分越界同样拒绝
    assertThatThrownBy(() -> ToolPortScope.requireWithinAuthorization(
        target("80,443"), "tcp_ports", ports("80,8080"), parser, 1024))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("8080");
  }

  @Test
  @DisplayName("宽授权范围 1-65535 不因展开而低效，且全部放行")
  void wideRangeIsAcceptedWithoutExpansion() {
    assertThatCode(() -> ToolPortScope.requireWithinAuthorization(
        target("1-65535"), "tcp_ports", ports("80,443,65535"), parser, 1024))
        .doesNotThrowAnyException();
  }

  @Test
  @DisplayName("未指定端口/非端口工具/空装配时不做拦截")
  void scopeCheckIsInertWhenNotApplicable() {
    assertThatCode(() -> ToolPortScope.requireWithinAuthorization(
        target("80"), "tcp_ports", Map.of(), parser, 1024)).doesNotThrowAnyException();
    assertThatCode(() -> ToolPortScope.requireWithinAuthorization(
        target("80"), "http_headers", ports("443"), parser, 1024)).doesNotThrowAnyException();
    assertThatCode(() -> ToolPortScope.requireWithinAuthorization(
        target("80"), "tcp_ports", ports("443"), null, 1024)).doesNotThrowAnyException();
  }

  @Test
  @DisplayName("端口串非法时报可读错误")
  void malformedPortSpecificationIsRejected() {
    assertThatThrownBy(() -> ToolPortScope.requireWithinAuthorization(
        target("80"), "tcp_ports", ports("bad-port"), parser, 1024))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("端口范围格式无效");
  }
}
