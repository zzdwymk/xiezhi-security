package com.bachelor.toolbox.target;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.project.AssessmentProjectRepository;
import com.bachelor.toolbox.project.ProjectAuthorizationService;
import com.bachelor.toolbox.project.ProjectTargetRepository;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;

/**
 * 第321轮：目标列表的分页读取必须有页数上限。
 *
 * <p>{@code TargetService.loadAll} 为保持数组 API 兼容，会循环读取所有页直到 {@code hasNext=false}。
 * 数据量很大时（或仓储异常持续返回 hasNext），一次列表请求会把全部目标读入内存。列表接口应设页数上限。
 */
class TargetListPageCapTests {

  @Test
  void listStopsAtTheConfiguredPageCap() {
    AuthorizedTargetRepository repository = mock(AuthorizedTargetRepository.class);
    AuditService auditService = mock(AuditService.class);
    AssessmentProjectRepository projects = mock(AssessmentProjectRepository.class);
    ProjectTargetRepository projectTargets = mock(ProjectTargetRepository.class);
    ProjectAuthorizationService authorization = mock(ProjectAuthorizationService.class);
    when(authorization.isAdmin()).thenReturn(true);

    AtomicInteger pageCalls = new AtomicInteger(0);
    when(repository.findAll(any(Pageable.class)))
        .thenAnswer(
            inv -> {
              Pageable pageable = inv.getArgument(0);
              int page = pageable.getPageNumber();
              pageCalls.incrementAndGet();
              List<AuthorizedTarget> content = new ArrayList<>();
              AuthorizedTarget target = new AuthorizedTarget();
              target.setId((long) page);
              target.setTargetValue("http://192.168.222.157/#" + page);
              content.add(target);
              // 总数 6 万，按 1000/页计算共 60 页
              return new PageImpl<>(content, pageable, 60_000L);
            });

    TargetService service =
        new TargetService(
            repository, auditService, new PortRangeParser(), projects, projectTargets, authorization, 65535);

    List<AuthorizedTarget> targets = service.list();

    assertThat(targets)
        .as("列表不允许无限翻页，必须在上限处停止（当前读取了 %s 页）", pageCalls.get())
        .hasSizeLessThanOrEqualTo(TargetService.MAX_LIST_PAGES);
    assertThat(pageCalls.get()).isLessThanOrEqualTo(TargetService.MAX_LIST_PAGES);
  }
}
