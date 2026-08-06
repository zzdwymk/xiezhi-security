package com.bachelor.toolbox.migration;

import javax.sql.DataSource;
import org.springframework.boot.autoconfigure.orm.jpa.EntityManagerFactoryDependsOnPostProcessor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/** Ensures the targeted legacy migration runs before Hibernate inspects or updates the schema. */
@Configuration(proxyBeanMethods = false)
public class LegacyProjectSchemaMigrationConfiguration {

  @Bean
  static EntityManagerFactoryDependsOnPostProcessor legacyProjectSchemaMigrationDependency() {
    return new EntityManagerFactoryDependsOnPostProcessor("legacyProjectSchemaMigration");
  }

  @Bean
  LegacyProjectSchemaMigration legacyProjectSchemaMigration(DataSource dataSource) {
    LegacyProjectSchemaMigration migration = new LegacyProjectSchemaMigration(dataSource);
    migration.migrate();
    return migration;
  }
}
