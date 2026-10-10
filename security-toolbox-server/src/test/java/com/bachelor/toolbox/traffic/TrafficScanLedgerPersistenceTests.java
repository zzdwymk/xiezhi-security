package com.bachelor.toolbox.traffic;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@DataJpaTest(showSql = false, properties = {
    "spring.datasource.url=jdbc:h2:mem:traffic-scan-lifecycle;MODE=PostgreSQL;DB_CLOSE_DELAY=-1",
    "spring.jpa.hibernate.ddl-auto=create-drop"
})
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Transactional(propagation = Propagation.NOT_SUPPORTED)
class TrafficScanLedgerPersistenceTests {
  @Autowired private TrafficScanLedgerRepository repository;

  @Test
  @Transactional
  void findingSourcesFilterBeforePaginationAndExcludeFuzzResponses() {
    repository.deleteAll();
    for (int i = 0; i < 14; i++) {
      TrafficScanLedger entry = new TrafficScanLedger();
      entry.setEngine(i == 0 ? "FUZZ" : i == 1 ? "XRAY" : "ZAP");
      entry.setPacketId((long) i);
      entry.setTargetId(2L);
      entry.setHost("fixture.invalid");
      entry.setPort(80);
      entry.setStatus("COMPLETED");
      entry.setHitCount(i < 3 ? 1 : 0);
      repository.save(entry);
    }
    var first = repository.findFindingSources(null, org.springframework.data.domain.PageRequest.of(0, 1));
    assertThat(first.getTotalElements()).isEqualTo(2);
    assertThat(first.getContent()).allMatch(entry -> entry.getHitCount() > 0 && !"FUZZ".equals(entry.getEngine()));
    assertThat(repository.findFindingSources(null, org.springframework.data.domain.PageRequest.of(1, 1)).getContent()).hasSize(1);
    assertThat(repository.findFindingSources("XRAY", org.springframework.data.domain.PageRequest.of(0, 10)).getTotalElements()).isEqualTo(1);
    assertThat(repository.findFindingSources("FUZZ", org.springframework.data.domain.PageRequest.of(0, 10)).getTotalElements()).isZero();
  }

  @Test
  void runningRecordIsVisibleAcrossTransactionsAndFinishesWithoutCreatingAnotherRow() {
    TrafficScanLedgerService service = new TrafficScanLedgerService(repository);
    TrafficScanLedger entry = new TrafficScanLedger();
    entry.setEngine("ZAP");
    entry.setPacketId(1L);
    entry.setTargetId(2L);
    entry.setHost("127.0.0.1");
    entry.setPort(8080);
    entry.setUrl("http://127.0.0.1:8080/page?id=1");

    service.begin(entry);

    Long id = entry.getId();
    assertThat(id).isPositive();
    TrafficScanLedger started = repository.findById(id).orElseThrow();
    assertThat(started.getStatus()).isEqualTo("RUNNING");
    assertThat(started.getStartedAt()).isNotNull();
    assertThat(started.getFinishedAt()).isNull();
    entry.setHitCount(1);
    entry.setResultJson("{\"status\":\"RUNNING\",\"hits\":[{\"title\":\"SQL Injection\"}]}");
    service.progress(entry);
    assertThat(repository.findById(id).orElseThrow().getResultJson()).contains("SQL Injection");

    entry.setStatus("COMPLETED");
    entry.setResultJson("{\"status\":\"COMPLETED\",\"hits\":[{\"title\":\"SQL Injection\"}]}");
    service.record(entry);

    TrafficScanLedger completed = repository.findById(id).orElseThrow();
    assertThat(repository.count()).isEqualTo(1);
    assertThat(completed.getStatus()).isEqualTo("COMPLETED");
    assertThat(completed.getHitCount()).isEqualTo(1);
    assertThat(completed.getResultJson()).contains("SQL Injection", "COMPLETED");
    assertThat(completed.getFinishedAt()).isNotNull();
    assertThat(completed.getCreatedAt()).isEqualTo(started.getCreatedAt());
  }
}
