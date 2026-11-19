package com.bachelor.toolbox.asset;

import static org.assertj.core.api.Assertions.assertThat;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.data.domain.PageRequest;

@DataJpaTest
class DiscoveredPathRepositoryIsolationTests {
  @Autowired DiscoveredPathRepository repository;

  private DiscoveredPath save(long project, long target, String suffix) {
    return repository.saveAndFlush(new DiscoveredPath(project, target,
        "http://192.168.222.158/" + suffix, "/" + suffix, "GET", "QA", 200, 1L, null));
  }

  @Test void projectAndTargetQueriesDoNotMixOtherOwnersRows() {
    var expected=save(1,2,"owned");save(3,2,"other-project");save(1,4,"other-target");
    assertThat(repository.findByProjectIdAndTargetIdOrderByDiscoveredAtDescIdDesc(1L,2L,PageRequest.of(0,10)))
        .extracting(DiscoveredPath::getId).containsExactly(expected.getId());
    assertThat(repository.existsByProjectIdAndTargetIdAndUrl(3L,2L,expected.getUrl())).isFalse();
    assertThat(repository.countByProjectIdAndTargetId(1L,2L)).isEqualTo(1);
    assertThat(repository.findByProjectIdAndTargetIdAndUrl(3L,2L,expected.getUrl())).isEmpty();
  }

  @Test void equalTimestampsUseDescendingIdAndRespectPageBudget() {
    var first=save(1,2,"first");var second=save(1,2,"second");
    Instant same=Instant.parse("2026-01-01T00:00:00Z");
    first.setDiscoveredAt(same);second.setDiscoveredAt(same);repository.flush();
    assertThat(repository.findByProjectIdOrderByDiscoveredAtDescIdDesc(1L,PageRequest.of(0,1)))
        .extracting(DiscoveredPath::getId).containsExactly(second.getId());
    assertThat(repository.findByProjectIdOrderByDiscoveredAtDescIdDesc(1L,PageRequest.of(1,1)))
        .extracting(DiscoveredPath::getId).containsExactly(first.getId());
  }
}
