package com.bachelor.toolbox.finding;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.project.ProjectAuthorizationService;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class FindingControllerTests {
  private final FindingRepository repository = mock(FindingRepository.class);
  private final com.bachelor.toolbox.task.SecurityTaskRepository taskRepository =
      mock(com.bachelor.toolbox.task.SecurityTaskRepository.class);
  private final AuditService auditService = mock(AuditService.class);
  private final ProjectAuthorizationService authorization = mock(ProjectAuthorizationService.class);
  private final FindingController controller =
      new FindingController(repository, taskRepository, auditService, authorization);

  {
    // 既有用例以管理员身份运行，行为与改造前一致；
    // 归属过滤与清空限制的专项覆盖见 FindingControllerAuthorizationTests。
    when(authorization.isAdmin()).thenReturn(true);
  }
  @Test
  void deletesSingleFinding() {
    Finding finding = new Finding();
    finding.setId(7L);
    finding.setTitle("Test finding");
    when(repository.findById(7L)).thenReturn(Optional.of(finding));

    controller.delete(7L);

    verify(repository).delete(finding);
    verify(auditService).record("DELETE_FINDING", "FINDING", 7L, "Test finding", "SUCCESS");
  }

  @Test
  void rejectsMissingFinding() {
    when(repository.findById(9L)).thenReturn(Optional.empty());

    assertThrows(ApiException.class, () -> controller.delete(9L));
  }

  @Test
  void clearsAllFindings() {
    when(repository.count()).thenReturn(12L);

    controller.clear();

    verify(repository).deleteAllInBatch();
    verify(auditService).record("CLEAR_FINDINGS", "FINDING", null, "deletedCount=12", "SUCCESS");
  }
}
