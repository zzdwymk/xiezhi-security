package com.bachelor.toolbox.finding;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;
import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.project.ProjectAuthorizationService;
import com.bachelor.toolbox.task.*;
import java.util.Optional;
import org.junit.jupiter.api.Test;
class FindingMutationBoundaryTests {
  @Test void foreignProjectMutationCannotSaveDeleteOrAudit() {
    var repository=mock(FindingRepository.class);var tasks=mock(SecurityTaskRepository.class);
    var audit=mock(AuditService.class);var auth=mock(ProjectAuthorizationService.class);
    var finding=new Finding();finding.setTaskId(4L);
    var task=new SecurityTask();task.setProjectId(7L);
    when(repository.findById(3L)).thenReturn(Optional.of(finding));when(tasks.findById(4L)).thenReturn(Optional.of(task));
    when(auth.requireAccess(7L)).thenThrow(new ApiException("无权访问该评估项目"));
    var controller=new FindingController(repository,tasks,audit,auth);
    assertThatThrownBy(()->controller.updateStatus(3L,new FindingController.StatusRequest("FIXED"))).isInstanceOf(ApiException.class);
    assertThatThrownBy(()->controller.delete(3L)).isInstanceOf(ApiException.class);
    verify(repository,never()).save(any());verify(repository,never()).delete(any(Finding.class));verifyNoInteractions(audit);
  }
  @Test void orphanFindingIsNotMutableByRegularUser() {
    var repository=mock(FindingRepository.class);var tasks=mock(SecurityTaskRepository.class);
    var audit=mock(AuditService.class);var auth=mock(ProjectAuthorizationService.class);
    when(repository.findById(3L)).thenReturn(Optional.of(new Finding()));
    var controller=new FindingController(repository,tasks,audit,auth);
    assertThatThrownBy(()->controller.delete(3L)).isInstanceOf(ApiException.class).hasMessage("结果记录不存在");
    verify(repository,never()).delete(any(Finding.class));verifyNoInteractions(audit,tasks);
  }
  @Test void nonAdminCannotClearEvenIfHttpSecurityChanges() {
    var repository=mock(FindingRepository.class);var tasks=mock(SecurityTaskRepository.class);
    var audit=mock(AuditService.class);var auth=mock(ProjectAuthorizationService.class);
    assertThatThrownBy(()->new FindingController(repository,tasks,audit,auth).clear()).isInstanceOf(ApiException.class);
    verifyNoInteractions(repository,audit,tasks);
  }
}
