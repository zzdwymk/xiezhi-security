package com.bachelor.toolbox.probe;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.project.ProjectAuthorizationService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * 第384轮：资产/探针探测端点的归属校验接线守卫。
 *
 * <p>{@code ProbeController} 的三个入口（发起探测、查询历史、删除结果）都以路径 {@code projectId}
 * 定位数据。若任一入口漏掉 {@code requireAccess}，普通用户即可对他人项目发起探测或读取/删除其资产节点。
 * 本测试锁定接线，并验证"拒绝时不得触达服务层"。
 */
@DisplayName("探针端点归属校验接线（第384轮）")
class ProbeControllerAuthorizationTests {
  private final ProbeService service = mock(ProbeService.class);
  private final ProjectAuthorizationService authorization = mock(ProjectAuthorizationService.class);
  private final ProbeController controller = new ProbeController(service, authorization);

  @Test
  @DisplayName("发起探测前必须校验项目访问权；拒绝时不得调用服务层")
  void probeChecksAccessBeforeDelegating() {
    when(authorization.requireAccess(7L)).thenThrow(new ApiException("无权访问该项目"));
    ProbeRequest request = new ProbeRequest();

    assertThatThrownBy(() -> controller.probe(7L, request)).isInstanceOf(ApiException.class);
    verify(authorization).requireAccess(7L);
    verify(service, never()).probe(any());
  }

  @Test
  @DisplayName("查询历史必须校验项目访问权；拒绝时不得调用服务层")
  void historyChecksAccessBeforeDelegating() {
    when(authorization.requireAccess(7L)).thenThrow(new ApiException("无权访问该项目"));

    assertThatThrownBy(() -> controller.history(7L, 9L)).isInstanceOf(ApiException.class);
    verify(authorization).requireAccess(7L);
    verify(service, never()).history(anyLong());
    verify(service, never()).history(anyLong(), anyLong());
  }

  @Test
  @DisplayName("删除结果必须校验项目访问权；拒绝时不得调用服务层")
  void deleteChecksAccessBeforeDelegating() {
    when(authorization.requireAccess(7L)).thenThrow(new ApiException("无权访问该项目"));

    assertThatThrownBy(() -> controller.delete(7L, 11L)).isInstanceOf(ApiException.class);
    verify(authorization).requireAccess(7L);
    verify(service, never()).delete(anyLong(), anyLong());
  }
}
