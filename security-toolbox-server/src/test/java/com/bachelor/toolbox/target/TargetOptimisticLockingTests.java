package com.bachelor.toolbox.target;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * 第287轮：并发编辑同一授权目标不得静默丢失更新。
 *
 * <p>两个运维同时打开同一目标详情时各自读到同一 version 的快照；先提交者的授权边界修改必须生效，
 * 后提交者应被乐观锁拒绝，而不是用自己的旧快照把它覆盖掉。
 */
@SpringBootTest(
    properties = {
      "spring.datasource.url=jdbc:h2:mem:target-version;MODE=PostgreSQL;DB_CLOSE_DELAY=-1",
      "spring.jpa.hibernate.ddl-auto=create-drop",
      "toolbox.auth.admin-password=test-admin-password-7bbbe095d8724fcb",
      "toolbox.auth.jwt-secret=test-jwt-secret-cdc24d415ad843aa9ef313028ae9be30",
      "toolbox.traffic.mitm-enabled=false",
      "toolbox.vulnerability-catalog.nuclei.import-on-startup=false",
      "toolbox.vulnerability-catalog.cisa-kev-enabled=false"
    })
class TargetOptimisticLockingTests {
  @Autowired private AuthorizedTargetRepository repository;
  @Autowired private TransactionTemplate transactions;

  @Test
  void staleSnapshotCannotOverwriteAnotherOperatorsAuthorizationChange() {
    Long id =
        transactions.execute(
            status -> {
              AuthorizedTarget target = new AuthorizedTarget();
              target.setName("并发目标");
              target.setTargetValue("http://192.168.222.158");
              target.setTargetType("URL");
              target.setAuthorizationNote("授权记录");
              target.setAllowedPorts("80,443");
              target.setEnabled(true);
              target.setAuthorizationExpiresAt(Instant.parse("2030-01-01T00:00:00Z"));
              return repository.saveAndFlush(target).getId();
            });

    // 两位运维各自读到同一版本（模拟两个已打开的详情页）
    AuthorizedTarget snapshotB =
        transactions.execute(status -> copyOf(repository.findById(id).orElseThrow()));

    // A 收窄授权端口并提交
    transactions.executeWithoutResult(
        status -> {
          AuthorizedTarget current = repository.findById(id).orElseThrow();
          current.setAllowedPorts("443");
          repository.saveAndFlush(current);
        });

    // B 基于旧快照提交自己的修改 → 必须被拒绝，而不是覆盖 A 的收窄
    assertThatThrownBy(
            () ->
                transactions.executeWithoutResult(
                    status -> {
                      AuthorizedTarget stale = repository.save(snapshotB);
                      stale.setAuthorizationNote("B 的备注");
                      repository.saveAndFlush(stale);
                    }))
        .isInstanceOf(OptimisticLockingFailureException.class);

    transactions.executeWithoutResult(
        status -> {
          AuthorizedTarget current = repository.findById(id).orElseThrow();
          assertThat(current.getAllowedPorts()).as("A 的授权收窄不能被 B 的旧快照覆盖").isEqualTo("443");
        });
  }

  private AuthorizedTarget copyOf(AuthorizedTarget source) {
    AuthorizedTarget copy = new AuthorizedTarget();
    copy.setId(source.getId());
    copy.setVersion(source.getVersion());
    copy.setName(source.getName());
    copy.setTargetValue(source.getTargetValue());
    copy.setTargetType(source.getTargetType());
    copy.setAuthorizationNote(source.getAuthorizationNote());
    copy.setAllowedPorts(source.getAllowedPorts());
    copy.setEnabled(source.isEnabled());
    copy.setAuthorizationValidFrom(source.getAuthorizationValidFrom());
    copy.setAuthorizationExpiresAt(source.getAuthorizationExpiresAt());
    return copy;
  }
}



