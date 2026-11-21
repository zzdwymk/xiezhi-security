package com.bachelor.toolbox.project;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * 第288轮：并发编辑同一评估项目不得静默丢失授权声明/时间窗修改。
 *
 * <p>项目级授权声明与授权时间窗是整套任务的授权来源；两个运维同时编辑同一项目时，
 * 后提交者不应能用旧快照把前者刚收窄的时间窗覆盖掉。
 */
@SpringBootTest(
    properties = {
      "spring.datasource.url=jdbc:h2:mem:project-version;MODE=PostgreSQL;DB_CLOSE_DELAY=-1",
      "spring.jpa.hibernate.ddl-auto=create-drop",
      "toolbox.auth.admin-password=test-admin-password-7bbbe095d8724fcb",
      "toolbox.auth.jwt-secret=test-jwt-secret-cdc24d415ad843aa9ef313028ae9be30",
      "toolbox.traffic.mitm-enabled=false",
      "toolbox.vulnerability-catalog.nuclei.import-on-startup=false",
      "toolbox.vulnerability-catalog.cisa-kev-enabled=false"
    })
class ProjectOptimisticLockingTests {
  @Autowired private AssessmentProjectRepository repository;
  @Autowired private TransactionTemplate transactions;

  @Test
  void staleSnapshotCannotOverwriteAnotherOperatorsAuthorizationWindow() {
    Long id =
        transactions.execute(
            status -> {
              AssessmentProject project = new AssessmentProject();
              project.setName("并发项目");
              project.setOwner("security-team");
              project.setStatus("ACTIVE");
              project.setAuthorizationStatement("原始授权声明");
              project.setAuthorizationValidFrom(Instant.parse("2026-01-01T00:00:00Z"));
              project.setAuthorizationExpiresAt(Instant.parse("2026-12-31T00:00:00Z"));
              return repository.saveAndFlush(project).getId();
            });

    AssessmentProject snapshotB =
        transactions.execute(status -> copyOf(repository.findById(id).orElseThrow()));

    // A 把授权到期日收窄到本月底
    Instant narrowed = Instant.parse("2026-01-31T00:00:00Z");
    transactions.executeWithoutResult(
        status -> {
          AssessmentProject current = repository.findById(id).orElseThrow();
          current.setAuthorizationExpiresAt(narrowed);
          repository.saveAndFlush(current);
        });

    // B 用旧快照提交自己的修改 → 必须被拒绝
    assertThatThrownBy(
            () ->
                transactions.executeWithoutResult(
                    status -> {
                      AssessmentProject stale = repository.save(snapshotB);
                      stale.setDescription("B 的说明");
                      repository.saveAndFlush(stale);
                    }))
        .isInstanceOf(OptimisticLockingFailureException.class);

    transactions.executeWithoutResult(
        status -> {
          AssessmentProject current = repository.findById(id).orElseThrow();
          assertThat(current.getAuthorizationExpiresAt())
              .as("A 的授权时间窗收窄不能被 B 的旧快照覆盖")
              .isEqualTo(narrowed);
        });
  }

  private AssessmentProject copyOf(AssessmentProject source) {
    AssessmentProject copy = new AssessmentProject();
    copy.setId(source.getId());
    copy.setName(source.getName());
    copy.setDescription(source.getDescription());
    copy.setOwner(source.getOwner());
    copy.setStatus(source.getStatus());
    copy.setAuthorizationStatement(source.getAuthorizationStatement());
    copy.setAuthorizationValidFrom(source.getAuthorizationValidFrom());
    copy.setAuthorizationExpiresAt(source.getAuthorizationExpiresAt());
    return copy;
  }
}

