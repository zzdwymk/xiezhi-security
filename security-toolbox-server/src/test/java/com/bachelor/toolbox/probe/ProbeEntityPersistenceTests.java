package com.bachelor.toolbox.probe;
import static org.assertj.core.api.Assertions.assertThat;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import jakarta.persistence.EntityManager;
@DataJpaTest
class ProbeEntityPersistenceTests {
 @Autowired ProbeResultRepository repository;
 @Autowired EntityManager entities;
 @Test void evidenceAndScopeSurviveDatabaseReload(){
  var r=new ProbeResult();r.setProjectId(7L);r.setTargetId(8L);r.setUrl("http://192.168.222.158/path");
  r.setEvidence("QA evidence <script>literal text</script>");r.setTechnologies("QA framework");
  Instant before=Instant.now();repository.saveAndFlush(r);Long id=r.getId();entities.clear();
  var loaded=repository.findById(id).orElseThrow();
  assertThat(loaded.getProjectId()).isEqualTo(7L);assertThat(loaded.getTargetId()).isEqualTo(8L);
  assertThat(loaded.getEvidence()).isEqualTo("QA evidence <script>literal text</script>");
  assertThat(loaded.getTechnologies()).isEqualTo("QA framework");assertThat(loaded.getDetectedAt()).isBetween(before,Instant.now());
 }
}
