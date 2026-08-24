package com.bachelor.toolbox.finding;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.project.ProjectAuthorizationService;
import com.bachelor.toolbox.task.SecurityTask;
import com.bachelor.toolbox.task.SecurityTaskRepository;
import java.util.Optional;
import org.junit.jupiter.api.Test;

/**
 * 结果接口的归属与权限校验。
 *
 * <p>此前 FindingController 直接操作 Repository，任何已认证用户都可以跨项目读写、删除，
 * 甚至清空全部结果。以下用例锁定修复后的行为，防止回归。
 */
class FindingControllerAuthorizationTests {
  private final FindingRepository repository = mock(FindingRepository.class);
  private final SecurityTaskRepository taskRepository = mock(SecurityTaskRepository.class);
  private final AuditService auditService = mock(AuditService.class);
  private final ProjectAuthorizationService authorization = mock(ProjectAuthorizationService.class);
  private final FindingController controller =
      new FindingController(repository, taskRepository, auditService, authorization);

  private Finding findingOwnedByProject(long findingId, long taskId, Long projectId) {
    Finding finding = new Finding();
    finding.setId(findingId);
    finding.setTaskId(taskId);
    finding.setTitle("测试漏洞");
    when(repository.findById(findingId)).thenReturn(Optional.of(finding));

    SecurityTask task = new SecurityTask();
    task.setId(taskId);
    task.setProjectId(projectId);
    when(taskRepository.findById(taskId)).thenReturn(Optional.of(task));
    return finding;
  }

  @Test
  void 非管理员删除他人项目的结果时被拒绝() {
    when(authorization.isAdmin()).thenReturn(false);
    findingOwnedByProject(7L, 70L, 700L);
    // 无权访问该项目
    when(authorization.requireAccess(700L)).thenThrow(new ApiException("无权访问该评估项目"));

    assertThatThrownBy(() -> controller.delete(7L)).isInstanceOf(ApiException.class);
    verify(repository, never()).delete(any(Finding.class));
  }

  @Test
  void 非管理员修改他人项目结果的状态时被拒绝() {
    when(authorization.isAdmin()).thenReturn(false);
    findingOwnedByProject(8L, 80L, 800L);
    when(authorization.requireAccess(800L)).thenThrow(new ApiException("无权访问该评估项目"));

    assertThatThrownBy(
            () -> controller.updateStatus(8L, new FindingController.StatusRequest("CONFIRMED")))
        .isInstanceOf(ApiException.class);
    verify(repository, never()).save(any(Finding.class));
  }

  @Test
  void 非管理员可以操作自己项目内的结果() {
    when(authorization.isAdmin()).thenReturn(false);
    Finding finding = findingOwnedByProject(9L, 90L, 900L);
    // requireAccess 不抛出即代表有权访问
    when(repository.save(finding)).thenReturn(finding);

    controller.delete(9L);

    verify(repository).delete(finding);
  }

  @Test
  void 非管理员清空全部结果时被拒绝() {
    when(authorization.isAdmin()).thenReturn(false);

    assertThatThrownBy(controller::clear)
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("仅管理员");
    verify(repository, never()).deleteAllInBatch();
  }

  @Test
  void 管理员可以清空全部结果() {
    when(authorization.isAdmin()).thenReturn(true);
    when(repository.count()).thenReturn(3L);

    controller.clear();

    verify(repository).deleteAllInBatch();
    verify(auditService).record("CLEAR_FINDINGS", "FINDING", null, "deletedCount=3", "SUCCESS");
  }

  @Test
  void 状态更新会回填瞬态的项目标识() {
    when(authorization.isAdmin()).thenReturn(true);
    Finding finding = findingOwnedByProject(10L, 100L, 1000L);
    when(repository.save(finding)).thenReturn(finding);
    when(taskRepository.findAllById(java.util.List.of(100L)))
        .thenReturn(java.util.List.of(taskWithProject(100L, 1000L)));

    Finding saved =
        controller.updateStatus(10L, new FindingController.StatusRequest("CONFIRMED"));

    // 若不回填，前端以响应覆盖行数据后会丢失项目上下文，
    // 导致「生成后续验证路径」立即不可用
    assertThat(saved.getProjectId()).isEqualTo(1000L);
  }

  private SecurityTask taskWithProject(long taskId, long projectId) {
    SecurityTask task = new SecurityTask();
    task.setId(taskId);
    task.setProjectId(projectId);
    return task;
  }
}
