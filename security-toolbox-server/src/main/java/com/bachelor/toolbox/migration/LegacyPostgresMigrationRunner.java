package com.bachelor.toolbox.migration;

import javax.sql.DataSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

/**
 * One-shot importer of legacy H2 data into PostgreSQL.
 *
 * <p>Only active under the {@code postgres} profile (so all H2-based tests and any H2 runtime are
 * unaffected). It runs after Hibernate has created/updated the target schema. When no legacy H2
 * URL was configured it is a no-op.
 */
@Profile("postgres")
@Component
public class LegacyPostgresMigrationRunner implements ApplicationRunner {
  private static final Logger log = LoggerFactory.getLogger(LegacyPostgresMigrationRunner.class);
  private final LegacyPostgresCopier copier;

  public LegacyPostgresMigrationRunner(DataSource postgresDataSource) {
    this.copier = new LegacyPostgresCopier(postgresDataSource);
  }

  @Override
  public void run(ApplicationArguments args) {
    try {
      int rows = copier.run();
      log.info("Legacy H2→PostgreSQL migration imported {} rows total.", rows);
    } catch (RuntimeException ex) {
      log.error("迁移 H2 历史数据失败，请检查 H2 文件是否被占用或损坏", ex);
    }
  }
}