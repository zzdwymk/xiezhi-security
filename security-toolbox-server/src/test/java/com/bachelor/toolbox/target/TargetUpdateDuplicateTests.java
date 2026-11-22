package com.bachelor.toolbox.target;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.project.AssessmentProject;
import com.bachelor.toolbox.project.AssessmentProjectRepository;
import com.bachelor.toolbox.project.ProjectAuthorizationService;
import com.bachelor.toolbox.project.ProjectTarget;
import com.bachelor.toolbox.project.ProjectTargetRepository;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;

/**
 * 第317轮：更新授权目标时也不得把它改指到同项目已存在的目标地址。
 *
 * <p>R316 只堵住了创建路径；`PUT /api/targets/{id}` 仍可把目标 B 的地址改成与目标 A 相同，
 * 从而绕过唯一性约束产生重复授权条目。
 */
class TargetUpdateDuplicateTests {

  @Test
  void updatingToAnExistingTargetValueInSameProjectIsRejected() {
    AuthorizedTargetRepository repository = mock(AuthorizedTargetRepository.class);
    AuditService auditService = mock(AuditService.class);
    AssessmentProjectRepository projects = mock(AssessmentProjectRepository.class);
    ProjectTargetRepository projectTargets = mock(ProjectTargetRepository.class);
    ProjectAuthorizationService authorization = mock(ProjectAuthorizationService.class);

    AssessmentProject project = new AssessmentProject();
    project.setId(519L);
    project.setStatus("ACTIVE");
    when(projects.findById(519L)).thenReturn(Optional.of(project));
    when(authorization.isAdmin()).thenReturn(true);

    AuthorizedTarget existing = new AuthorizedTarget();
    existing.setId(1L);
    existing.setTargetValue("http://192.168.222.157/");
    when(repository.findById(1L)).thenReturn(Optional.of(existing));

    AuthorizedTarget toUpdate = new AuthorizedTarget();
    toUpdate.setId(2L);
    toUpdate.setName("待改目标");
    toUpdate.setTargetValue("http://192.168.222.157/other");
    toUpdate.setTargetType("URL");
    toUpdate.setAuthorizationNote("授权");
    toUpdate.setAllowedPorts("80");
    toUpdate.setEnabled(true);
    when(repository.findById(2L)).thenReturn(Optional.of(toUpdate));
    when(repository.save(any(AuthorizedTarget.class))).thenAnswer(inv -> inv.getArgument(0));

    when(projectTargets.findByTargetId(2L)).thenReturn(List.of(new ProjectTarget(519L, 2L)));
    when(projectTargets.findByProjectIdAndTargetId(519L, 2L))
        .thenReturn(Optional.of(new ProjectTarget(519L, 2L)));
    when(projectTargets.findByProjectId(519L))
        .thenReturn(List.of(new ProjectTarget(519L, 1L), new ProjectTarget(519L, 2L)));

    TargetService service =
        new TargetService(
            repository, auditService, new PortRangeParser(), projects, projectTargets, authorization, 65535);

    TargetRequest request =
        new TargetRequest(
            "待改目标",
            "http://192.168.222.157/",
            "URL",
            "授权",
            "80",
            true,
            null,
            null,
            519L);

    assertThatThrownBy(() -> service.update(2L, request))
        .as("把目标改指到同项目已存在的地址必须被拒绝")
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("已存在相同目标");
  }
}

