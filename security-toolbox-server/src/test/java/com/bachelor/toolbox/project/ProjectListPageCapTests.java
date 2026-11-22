package com.bachelor.toolbox.project;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.audit.AuditLogRepository;
import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.finding.FindingRepository;
import com.bachelor.toolbox.target.AuthorizedTargetRepository;
import com.bachelor.toolbox.task.SecurityTaskRepository;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;

/**
 * 第322轮：项目列表的分页读取必须有页数上限。
 *
 * <p>与 R321 的目标列表同源：{@code AssessmentProjectService.loadAll} 一直翻页到 hasNext=false。
 * 项目数量很大时，一次 `GET /api/projects` 会把全部项目读入内存。
 */
class ProjectListPageCapTests {

  @Test
  void listStopsAtTheConfiguredPageCap() {
    AssessmentProjectRepository projects = mock(AssessmentProjectRepository.class);
    ProjectTargetRepository links = mock(ProjectTargetRepository.class);
    AuthorizedTargetRepository targets = mock(AuthorizedTargetRepository.class);
    AuditService audit = mock(AuditService.class);
    SecurityTaskRepository taskRepository = mock(SecurityTaskRepository.class);
    FindingRepository findingRepository = mock(FindingRepository.class);
    AuditLogRepository auditRepository = mock(AuditLogRepository.class);
    ProjectAuthorizationService authorization = mock(ProjectAuthorizationService.class);
    when(authorization.isAdmin()).thenReturn(true);

    AtomicInteger pageCalls = new AtomicInteger(0);
    when(projects.findAll(any(Pageable.class)))
        .thenAnswer(
            inv -> {
              Pageable pageable = inv.getArgument(0);
              int page = pageable.getPageNumber();
              pageCalls.incrementAndGet();
              List<AssessmentProject> content = new ArrayList<>();
              AssessmentProject project = new AssessmentProject();
              project.setId((long) page);
              project.setName("项目" + page);
              content.add(project);
              return new PageImpl<>(content, pageable, 60_000L);
            });

    AssessmentProjectService service =
        new AssessmentProjectService(
            projects, links, targets, audit, taskRepository, findingRepository, auditRepository, authorization);

    List<AssessmentProject> result = service.list();

    assertThat(pageCalls.get())
        .as("项目列表不允许无限翻页（当前读取了 %s 页）", pageCalls.get())
        .isLessThanOrEqualTo(AssessmentProjectService.MAX_LIST_PAGES);
    assertThat(result).hasSizeLessThanOrEqualTo(AssessmentProjectService.MAX_LIST_PAGES);
  }
}
