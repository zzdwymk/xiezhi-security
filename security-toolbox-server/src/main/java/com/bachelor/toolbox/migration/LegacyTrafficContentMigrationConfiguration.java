package com.bachelor.toolbox.migration;

import javax.sql.DataSource;
import org.springframework.boot.autoconfigure.orm.jpa.EntityManagerFactoryDependsOnPostProcessor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration(proxyBeanMethods = false)
public class LegacyTrafficContentMigrationConfiguration {
  @Bean
  static EntityManagerFactoryDependsOnPostProcessor legacyTrafficContentMigrationDependency() {
    return new EntityManagerFactoryDependsOnPostProcessor("legacyTrafficContentMigration");
  }

  @Bean
  LegacyTrafficContentMigration legacyTrafficContentMigration(DataSource dataSource) {
    LegacyTrafficContentMigration migration = new LegacyTrafficContentMigration(dataSource);
    migration.migrate();
    return migration;
  }
}
