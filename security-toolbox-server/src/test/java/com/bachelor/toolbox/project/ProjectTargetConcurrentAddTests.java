package com.bachelor.toolbox.project;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.audit.AuditLogRepository;
import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.finding.FindingRepository;
import com.bachelor.toolbox.target.AuthorizedTargetRepository;
import com.bachelor.toolbox.task.SecurityTaskRepository;
import java.time.Instant;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataIntegrityViolationException;

/**
 * 第320轮：并发把同一目标加入同一项目时，唯一约束冲突必须转成可读业务错误。
 *
 * <p>`addTarget` 是"先查后写"：两个并发请求都能通过 `validateTargetCanBeAdded`，随后数据库
 * `(projectId,targetId)` 唯一约束拦下第二个，抛 {@code DataIntegrityViolationException}，
 * 被全局异常处理器归类为 500「数据库访问失败」。正确行为是返回可读的"目标已在项目中"。
 */
class ProjectTargetConcurrentAddTests {

  @Test
  void uniqueConstraintViolationIsTranslatedToBusinessError() {
    AssessmentProjectRepository projects = mock(AssessmentProjectRepository.class);
    ProjectTargetRepository links = mock(ProjectTargetRepository.class);
    AuthorizedTargetRepository targets = mock(AuthorizedTargetRepository.class);
    AuditService audit = mock(AuditService.class);
    SecurityTaskRepository taskRepository = mock(SecurityTaskRepository.class);
    FindingRepository findingRepository = mock(FindingRepository.class);
    AuditLogRepository auditRepository = mock(AuditLogRepository.class);
    ProjectAuthorizationService authorization = mock(ProjectAuthorizationService.class);

    AssessmentProject project = new AssessmentProject();
    project.setId(519L);
    project.setStatus("ACTIVE");
    project.setAuthorizationValidFrom(Instant.now().minusSeconds(3600));
    project.setAuthorizationExpiresAt(Instant.now().plusSeconds(3600));
    when(authorization.requireAccess(519L)).thenReturn(project);
    when(targets.existsById(9L)).thenReturn(true);
    when(links.findByProjectIdAndTargetId(519L, 9L)).thenReturn(Optional.empty());
    when(links.save(any(ProjectTarget.class)))
        .thenThrow(new DataIntegrityViolationException("duplicate key"));
    when(links.saveAndFlush(any(ProjectTarget.class)))
        .thenThrow(new DataIntegrityViolationException("duplicate key"));

    AssessmentProjectService service =
        new AssessmentProjectService(
            projects, links, targets, audit, taskRepository, findingRepository, auditRepository, authorization);

    assertThatThrownBy(() -> service.addTarget(519L, 9L))
        .as("唯一约束冲突必须转成可读业务错误，而不是 500")
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("目标已在项目中");
  }
}
