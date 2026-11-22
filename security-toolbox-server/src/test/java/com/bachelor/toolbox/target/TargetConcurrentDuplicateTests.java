package com.bachelor.toolbox.target;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.audit.AuditService;
import com.bachelor.toolbox.project.AssessmentProject;
import com.bachelor.toolbox.project.AssessmentProjectRepository;
import com.bachelor.toolbox.project.ProjectAuthorizationService;
import com.bachelor.toolbox.project.ProjectTarget;
import com.bachelor.toolbox.project.ProjectTargetRepository;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

/**
 * 第318轮：同一项目并发创建相同目标必须严格串行，只能有一个成功。
 *
 * <p>R316/R317 的重复校验是"先查后写"。并发时多个请求会同时通过检查各自保存（实测 5 个并发请求
 * 可产生多个成功）。本轮用项目级锁串行化创建；测试直接测量并发保存的峰值与成功数。
 */
class TargetConcurrentDuplicateTests {

  @Test
  void concurrentCreatesOfSameTargetAreSerialized() throws Exception {
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

    CopyOnWriteArrayList<ProjectTarget> links = new CopyOnWriteArrayList<>();
    when(projectTargets.findByProjectId(519L)).thenAnswer(inv -> List.copyOf(links));
    when(projectTargets.save(any(ProjectTarget.class)))
        .thenAnswer(
            inv -> {
              ProjectTarget link = inv.getArgument(0);
              links.add(link);
              return link;
            });

    AtomicInteger ids = new AtomicInteger(0);
    AtomicInteger activeSaves = new AtomicInteger(0);
    AtomicInteger maxActiveSaves = new AtomicInteger(0);
    ConcurrentHashMap<Long, AuthorizedTarget> savedTargets = new ConcurrentHashMap<>();
    when(repository.save(any(AuthorizedTarget.class)))
        .thenAnswer(
            inv -> {
              int now = activeSaves.incrementAndGet();
              maxActiveSaves.accumulateAndGet(now, Math::max);
              try {
                Thread.sleep(150);
              } catch (InterruptedException ex) {
                Thread.currentThread().interrupt();
              } finally {
                activeSaves.decrementAndGet();
              }
              AuthorizedTarget target = inv.getArgument(0);
              long id = ids.incrementAndGet();
              target.setId(id);
              savedTargets.put(id, target);
              return target;
            });
    when(repository.findById(anyLong()))
        .thenAnswer(inv -> Optional.ofNullable(savedTargets.get(inv.getArgument(0))));

    TargetService service =
        new TargetService(
            repository, auditService, new PortRangeParser(), projects, projectTargets, authorization, 65535);

    TargetRequest request =
        new TargetRequest(
            "并发重复目标",
            "http://192.168.222.157/",
            "URL",
            "并发重复探测",
            "80",
            true,
            null,
            null,
            519L);

    ExecutorService pool = Executors.newFixedThreadPool(5);
    try {
      List<Future<Boolean>> futures = new ArrayList<>();
      for (int i = 0; i < 5; i++) {
        futures.add(
            pool.submit(
                () -> {
                  try {
                    service.create(request);
                    return true;
                  } catch (RuntimeException ex) {
                    return false;
                  }
                }));
      }
      int successes = 0;
      for (Future<Boolean> future : futures) {
        if (future.get(30, TimeUnit.SECONDS)) successes++;
      }
      assertThat(maxActiveSaves.get())
          .as("同一项目的目标创建不得并发执行（否则重复校验失效），并发保存峰值=%s", maxActiveSaves.get())
          .isLessThanOrEqualTo(1);
      assertThat(successes)
          .as("5 个并发相同目标创建只能有 1 个成功，实际=%s", successes)
          .isEqualTo(1);
    } finally {
      pool.shutdownNow();
    }
  }
}
