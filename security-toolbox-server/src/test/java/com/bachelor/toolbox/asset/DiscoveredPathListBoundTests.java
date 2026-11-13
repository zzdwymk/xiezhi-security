package com.bachelor.toolbox.asset;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.target.TargetPolicyService;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.data.domain.Pageable;

/** 已发现路径列表查询必须有界——Round 41。 */
@DisplayName("已发现路径列表有界（Round 41）")
class DiscoveredPathListBoundTests {
  private final DiscoveredPathRepository repository = mock(DiscoveredPathRepository.class);
  private final DiscoveredPathService service =
      new DiscoveredPathService(repository, mock(TargetPolicyService.class));

  @Test
  @DisplayName("DP-1 listByProject 走分页重载且上限≤MAX_LIST_ROWS")
  void listByProjectBounded() {
    when(repository.findByProjectIdOrderByDiscoveredAtDescIdDesc(eq(1L), any()))
        .thenReturn(List.of());
    service.listByProject(1L);
    ArgumentCaptor<Pageable> cap = ArgumentCaptor.forClass(Pageable.class);
    verify(repository).findByProjectIdOrderByDiscoveredAtDescIdDesc(eq(1L), cap.capture());
    assertThat(cap.getValue().getPageSize()).isEqualTo(DiscoveredPathService.MAX_LIST_ROWS);
    assertThat(cap.getValue().getPageSize()).isLessThanOrEqualTo(20_000);
  }

  @Test
  @DisplayName("DP-2 listByTarget 走分页重载且上限≤MAX_LIST_ROWS")
  void listByTargetBounded() {
    when(repository.findByTargetIdOrderByDiscoveredAtDescIdDesc(eq(7L), any()))
        .thenReturn(List.of());
    service.listByTarget(7L);
    ArgumentCaptor<Pageable> cap = ArgumentCaptor.forClass(Pageable.class);
    verify(repository).findByTargetIdOrderByDiscoveredAtDescIdDesc(eq(7L), cap.capture());
    assertThat(cap.getValue().getPageSize()).isEqualTo(DiscoveredPathService.MAX_LIST_ROWS);
  }
}
