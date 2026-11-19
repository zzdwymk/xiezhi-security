package com.bachelor.toolbox.probe;
import static org.assertj.core.api.Assertions.assertThat;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.data.domain.PageRequest;
@DataJpaTest
class ProbeRepositoryBoundaryTests {
 @Autowired ProbeResultRepository repository;
 private ProbeResult save(long project,long target){var r=new ProbeResult();r.setProjectId(project);r.setTargetId(target);r.setUrl("http://192.168.222.158");return repository.saveAndFlush(r);}
 @Test void projectTargetFilterDoesNotReturnOtherProjectsRows(){
  var expected=save(1,2);save(3,2);save(1,4);
  assertThat(repository.findByProjectIdAndTargetIdOrderByDetectedAtDescIdDesc(1L,2L,PageRequest.of(0,10))).extracting(ProbeResult::getId).containsExactly(expected.getId());
 }
 @Test void equalDetectionTimesRemainStablyPagedById(){
  var first=save(1,2);var second=save(1,2);var same=Instant.parse("2026-01-01T00:00:00Z");first.setDetectedAt(same);second.setDetectedAt(same);repository.flush();
  assertThat(repository.findByProjectIdOrderByDetectedAtDescIdDesc(1L,PageRequest.of(0,1))).extracting(ProbeResult::getId).containsExactly(second.getId());
  assertThat(repository.findByProjectIdOrderByDetectedAtDescIdDesc(1L,PageRequest.of(1,1))).extracting(ProbeResult::getId).containsExactly(first.getId());
 }
}
