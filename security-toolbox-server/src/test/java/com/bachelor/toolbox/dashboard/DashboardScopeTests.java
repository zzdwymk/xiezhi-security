package com.bachelor.toolbox.dashboard;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.finding.FindingRepository;
import com.bachelor.toolbox.project.ProjectAuthorizationService;
import com.bachelor.toolbox.target.AuthorizedTargetRepository;
import com.bachelor.toolbox.task.SecurityTaskRepository;
import java.util.List;
import org.junit.jupiter.api.Test;

/** Round 230：仪表盘聚合必须按当前用户可访问项目范围过滤。 */
class DashboardScopeTests {

  private final AuthorizedTargetRepository targets = mock(AuthorizedTargetRepository.class);
  private final SecurityTaskRepository tasks = mock(SecurityTaskRepository.class);
  private final FindingRepository findings = mock(FindingRepository.class);
  private final ProjectAuthorizationService authorization = mock(ProjectAuthorizationService.class);
  private final DashboardController controller =
      new DashboardController(targets, tasks, findings, authorization);

  @Test
  void 管理员仍然看到全局聚合() {
    when(authorization.isAdmin()).thenReturn(true);
    when(targets.count()).thenReturn(10L);
    when(tasks.countByStatus("RUNNING")).thenReturn(2L);
    when(findings.count()).thenReturn(7L);
    when(findings.countBySeverityIn(List.of("HIGH", "CRITICAL"))).thenReturn(3L);

    assertThat(controller.summary())
        .containsEntry("targets", 10L)
        .containsEntry("running", 2L)
        .containsEntry("findings", 7L)
        .containsEntry("critical", 3L);
  }

  @Test
  void 普通用户只看到可访问项目聚合() {
    when(authorization.isAdmin()).thenReturn(false);
    when(authorization.accessibleProjectIds()).thenReturn(List.of(1L, 2L));
    when(targets.countAccessibleByProjectIds(anyCollection())).thenReturn(4L);
    when(tasks.countByProjectIdInAndStatusIn(anyCollection(), anyCollection())).thenReturn(1L);
    when(findings.countByProjectIds(anyCollection())).thenReturn(5L);
    when(findings.countByProjectIdsAndSeverityIn(anyCollection(), anyCollection())).thenReturn(2L);

    assertThat(controller.summary())
        .containsEntry("targets", 4L)
        .containsEntry("running", 1L)
        .containsEntry("findings", 5L)
        .containsEntry("critical", 2L);
    verify(targets, never()).count();
    verify(findings, never()).count();
  }

  @Test
  void 无项目普通用户返回零值() {
    when(authorization.isAdmin()).thenReturn(false);
    when(authorization.accessibleProjectIds()).thenReturn(List.of());

    assertThat(controller.summary())
        .containsEntry("targets", 0L)
        .containsEntry("running", 0L)
        .containsEntry("findings", 0L)
        .containsEntry("critical", 0L);
  }
}
