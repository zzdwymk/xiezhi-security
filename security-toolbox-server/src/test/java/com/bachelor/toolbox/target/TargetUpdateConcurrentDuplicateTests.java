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
 * 第319轮：并发更新两个目标、把它们改指到同一地址时，只能有一个成功。
 *
 * <p>R317 给 update 加了重复校验，但同样是"先查后写"；R318 只给 create 加锁。两个并发 PUT 可以同时
 * 通过检查各自保存，产生重复授权目标。本轮把 update 也纳入项目级锁。
 */
class TargetUpdateConcurrentDuplicateTests {

  @Test
  void concurrentUpdatesToSameValueAreSerialized() throws Exception {
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

    AuthorizedTarget first = target(1L, "http://192.168.222.157/?r319=first");
    AuthorizedTarget second = target(2L, "http://192.168.222.157/?r319=second");
    ConcurrentHashMap<Long, AuthorizedTarget> byId = new ConcurrentHashMap<>();
    byId.put(1L, first);
    byId.put(2L, second);
    when(repository.findById(anyLong()))
        .thenAnswer(inv -> Optional.ofNullable(byId.get(inv.getArgument(0))));

    CopyOnWriteArrayList<ProjectTarget> links = new CopyOnWriteArrayList<>();
    links.add(new ProjectTarget(519L, 1L));
    links.add(new ProjectTarget(519L, 2L));
    when(projectTargets.findByProjectId(519L)).thenAnswer(inv -> List.copyOf(links));
    when(projectTargets.findByTargetId(anyLong()))
        .thenAnswer(
            inv ->
                links.stream()
                    .filter(link -> link.getTargetId().equals(inv.getArgument(0)))
                    .toList());
    when(projectTargets.findByProjectIdAndTargetId(anyLong(), anyLong()))
        .thenAnswer(
            inv ->
                links.stream()
                    .filter(
                        link ->
                            link.getProjectId().equals(inv.getArgument(0))
                                && link.getTargetId().equals(inv.getArgument(1)))
                    .findFirst());

    AtomicInteger activeSaves = new AtomicInteger(0);
    AtomicInteger maxActiveSaves = new AtomicInteger(0);
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
              return inv.getArgument(0);
            });

    TargetService service =
        new TargetService(
            repository, auditService, new PortRangeParser(), projects, projectTargets, authorization, 65535);

    TargetRequest rename =
        new TargetRequest(
            "并发改指",
            "http://192.168.222.157/?r319=same",
            "URL",
            "并发改指探测",
            "80",
            true,
            null,
            null,
            519L);

    ExecutorService pool = Executors.newFixedThreadPool(2);
    try {
      List<Future<Boolean>> futures = new ArrayList<>();
      long[] ids = {1L, 2L};
      for (long id : ids) {
        futures.add(
            pool.submit(
                () -> {
                  try {
                    service.update(id, rename);
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
          .as("同一项目的目标更新不得并发执行，并发保存峰值=%s", maxActiveSaves.get())
          .isLessThanOrEqualTo(1);
      assertThat(successes)
          .as("并发把两个目标改指到同一地址只能有一个成功，实际=%s", successes)
          .isEqualTo(1);
    } finally {
      pool.shutdownNow();
    }
  }

  private static AuthorizedTarget target(long id, String value) {
    AuthorizedTarget target = new AuthorizedTarget();
    target.setId(id);
    target.setName("目标" + id);
    target.setTargetValue(value);
    target.setTargetType("URL");
    target.setAuthorizationNote("授权");
    target.setAllowedPorts("80");
    target.setEnabled(true);
    return target;
  }
}
