package com.bachelor.toolbox.asset;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.recon.ReconController;
import com.bachelor.toolbox.recon.ReconService;
import com.bachelor.toolbox.target.TargetService;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * 跨项目/跨目标越权（IDOR）回归——Round 11。
 *
 * <p>修复前：
 * <ul>
 *   <li>{@code GET /api/projects/{id}/recon/paths} 直接调用 {@code DiscoveredPathService.listByProject}
 *       读取任意项目已发现路径，无归属校验；
 *   <li>{@code GET /api/targets/{id}/discovered-paths} 直接按 targetId 返回，无授权目标校验。
 * </ul>
 * 修复后在控制器入口强制归属校验（requireAccess / targets.get）。本类锁定该行为。
 */
@DisplayName("资产/信息收集读取越权（IDOR）Round 11")
class AssetAccessControlTests {

  private final DiscoveredPathService paths = mock(DiscoveredPathService.class);
  private final TargetService targets = mock(TargetService.class);
  private final com.bachelor.toolbox.project.ProjectAuthorizationService authorization =
      mock(com.bachelor.toolbox.project.ProjectAuthorizationService.class);
  private final ReconService reconService = mock(ReconService.class);

  @Test
  @DisplayName("IDOR-1 无权访问项目时 recon/paths 读取被拒，且不进仓储")
  void reconPathsRejectsInaccessibleProject() {
    ReconController c = new ReconController(reconService, paths, authorization);
    when(authorization.requireAccess(42L)).thenThrow(new ApiException("无权访问该评估项目"));

    assertThatThrownBy(() -> c.paths(42L, null))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("无权访问");
    verify(paths, never()).listByProject(42L);
  }

  @Test
  @DisplayName("IDOR-2 有权访问项目时 recon/paths 正常返回")
  void reconPathsAllowsAccessibleProject() {
    ReconController c = new ReconController(reconService, paths, authorization);
    when(paths.listByProject(1L)).thenReturn(List.of());
    c.paths(1L, null);
    verify(authorization).requireAccess(1L);
    verify(paths).listByProject(1L);
  }

  @Test
  @DisplayName("IDOR-3 redesign/targets/{id}/discovered-paths 对无权目标被拒")
  void discoveredPathsByTargetRejectsInaccessibleTarget() {
    DiscoveredPathController c = new DiscoveredPathController(paths, targets);
    when(targets.get(9L)).thenThrow(new ApiException("无权访问该授权目标"));

    assertThatThrownBy(() -> c.list(9L))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("无权访问");
    verify(paths, never()).listByTarget(9L);
  }

  @Test
  @DisplayName("IDOR-4 有权目标时 discovered-paths 正常返回")
  void discoveredPathsByTargetAllowsAccessible() {
    DiscoveredPathController c = new DiscoveredPathController(paths, targets);
    when(paths.listByTarget(9L)).thenReturn(List.of());
    c.list(9L);
    verify(targets).get(9L);
    verify(paths).listByTarget(9L);
  }

  @Test
  @DisplayName("IDOR-5 recon/results 对无权项目也被拒（纵深：即便服务已守卫，控制器亦守卫）")
  void reconResultsRejectsInaccessibleProject() {
    ReconController c = new ReconController(reconService, paths, authorization);
    when(authorization.requireAccess(77L)).thenThrow(new ApiException("无权访问该评估项目"));

    assertThatThrownBy(() -> c.results(77L, null)).isInstanceOf(ApiException.class);
    verify(reconService, never()).history(77L);
  }
}
