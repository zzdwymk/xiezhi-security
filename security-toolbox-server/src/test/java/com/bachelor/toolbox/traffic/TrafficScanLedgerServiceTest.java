package com.bachelor.toolbox.traffic;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.common.ApiException;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;

@ExtendWith(MockitoExtension.class)
class TrafficScanLedgerServiceTests {
  private final TrafficScanLedgerRepository repository = mock(TrafficScanLedgerRepository.class);
  private final TrafficScanLedgerService service = new TrafficScanLedgerService(repository);

  @Test
  void recordsAnEntry() {
    TrafficScanLedger entry = new TrafficScanLedger();
    entry.setEngine("SQLMAP");
    when(repository.save(entry)).thenReturn(entry);
    assertThat(service.record(entry)).isSameAs(entry);
  }

  @Test
  void listsAllEntriesByDefault() {
    when(repository.findAllByOrderByCreatedAtDesc(any(Pageable.class)))
        .thenReturn(new PageImpl<>(List.of(entry())));
    Page<TrafficScanLedger> page = service.list(0, 20, null);
    assertThat(page.getContent()).hasSize(1);
  }

  @Test
  void filtersByEngine() {
    when(repository.findByEngineOrderByCreatedAtDesc(eq("XRAY"), any(Pageable.class)))
        .thenReturn(new PageImpl<>(List.of(entry())));
    Page<TrafficScanLedger> page = service.list(0, 20, "xray");
    assertThat(page.getContent()).hasSize(1);
  }

  @Test
  void rejectsUnknownEngine() {
    assertThatThrownBy(() -> service.list(0, 20, "bogus"))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("未知扫描引擎");
  }

  private TrafficScanLedger entry() {
    return new TrafficScanLedger();
  }
}