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
 * 第316轮：同一项目内不得重复登记完全相同的授权目标。
 *
 * <p>实测通过 {@code POST /api/targets} 连续提交同一 {@code targetValue} 两次会同时成功（201/201），
 * 产生重复授权条目：任务可任选其一、审计里出现两个同地址目标、删除也需逐个处理。授权目标应当在同一
 * 项目内保持唯一（同一地址重复登记不会带来任何额外授权信息）。
 */
class TargetDuplicateRegistrationTests {

  @Test
  void duplicateTargetValueInSameProjectIsRejected() {
    AuthorizedTargetRepository repository = mock(AuthorizedTargetRepository.class);
    AuditService auditService = mock(AuditService.class);
    AssessmentProjectRepository projects = mock(AssessmentProjectRepository.class);
    ProjectTargetRepository projectTargets = mock(ProjectTargetRepository.class);
    ProjectAuthorizationService authorization = mock(ProjectAuthorizationService.class);

    AssessmentProject project = new AssessmentProject();
    project.setId(519L);
    project.setStatus("ACTIVE");
    when(projects.findById(519L)).thenReturn(Optional.of(project));

    AuthorizedTarget existing = new AuthorizedTarget();
    existing.setId(1L);
    existing.setTargetValue("http://192.168.222.157/");
    when(repository.findById(1L)).thenReturn(Optional.of(existing));
    when(projectTargets.findByProjectId(519L)).thenReturn(List.of(new ProjectTarget(519L, 1L)));
    when(repository.save(any(AuthorizedTarget.class))).thenAnswer(inv -> inv.getArgument(0));

    TargetService service =
        new TargetService(
            repository, auditService, new PortRangeParser(), projects, projectTargets, authorization, 65535);

    TargetRequest request =
        new TargetRequest(
            "重复目标",
            "http://192.168.222.157/",
            "URL",
            "重复登记探测",
            "80",
            true,
            null,
            null,
            519L);

    assertThatThrownBy(() -> service.create(request))
        .as("同一项目内重复登记相同目标地址必须被拒绝")
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("已存在相同目标");
  }
}

