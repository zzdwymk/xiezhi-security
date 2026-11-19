package com.bachelor.toolbox.asset;
import static org.assertj.core.api.Assertions.assertThat;
import java.time.Instant;
import jakarta.persistence.Column;
import org.junit.jupiter.api.Test;
class DiscoveredPathEntityContractTests {
  @Test void constructorPreservesEvidenceAndDefaultsOnlyMissingMethod() {
    var path=new DiscoveredPath(1L,2L,"http://192.168.222.158/a?x=1","/a?x=1",null,"CRAWL",200,42L,"QA evidence");
    assertThat(path.getProjectId()).isEqualTo(1L);assertThat(path.getTargetId()).isEqualTo(2L);
    assertThat(path.getUrl()).isEqualTo("http://192.168.222.158/a?x=1");
    assertThat(path.getPath()).isEqualTo("/a?x=1");assertThat(path.getMethod()).isEqualTo("GET");
    assertThat(path.getNote()).isEqualTo("QA evidence");
  }
  @Test void persistenceAllocatesCurrentTimestamp() {
    var path=new DiscoveredPath();Instant before=Instant.now();path.prePersist();Instant after=Instant.now();
    assertThat(path.getDiscoveredAt()).isBetween(before,after);
  }
  @Test void databaseColumnBudgetsRemainExplicit() throws Exception {
    assertThat(DiscoveredPath.class.getDeclaredField("url").getAnnotation(Column.class).length()).isEqualTo(2048);
    assertThat(DiscoveredPath.class.getDeclaredField("path").getAnnotation(Column.class).length()).isEqualTo(2048);
    assertThat(DiscoveredPath.class.getDeclaredField("note").getAnnotation(Column.class).length()).isEqualTo(500);
  }
}
