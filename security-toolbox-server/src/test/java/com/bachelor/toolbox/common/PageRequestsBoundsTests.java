package com.bachelor.toolbox.common;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;

/**
 * 第416轮：分页边界护栏回归。
 *
 * <p>{@link PageRequests} 是全站列表接口共用的分页入口；一旦有人改坏钳制逻辑，
 * 调用方（审计日志 500 / 发现 100 / 漏洞目录 200）就可能被单个请求拉取超大结果集。
 * 这里把“上限、下限、负页码、非法边界配置”四项行为钉成测试。
 */
@DisplayName("分页边界钳制（Round 416）")
class PageRequestsBoundsTests {

  @Test
  @DisplayName("PG-1 超出上限的页大小被钳到 max")
  void clampsOversizedPage() {
    PageRequest request = PageRequests.bounded(0, 1_000_000, 1, 200, Sort.unsorted());
    assertThat(request.getPageSize()).isEqualTo(200);
    assertThat(request.getPageNumber()).isZero();
  }

  @Test
  @DisplayName("PG-2 小于下限的页大小被抬到 min")
  void raisesUndersizedPage() {
    PageRequest request = PageRequests.bounded(0, 1, 10, 100, Sort.unsorted());
    assertThat(request.getPageSize()).isEqualTo(10);
  }

  @Test
  @DisplayName("PG-3 负页码按 0 处理，不产生非法 PageRequest")
  void negativePageBecomesZero() {
    PageRequest request = PageRequests.bounded(-5, 50, 1, 200, Sort.unsorted());
    assertThat(request.getPageNumber()).isZero();
    assertThat(request.getPageSize()).isEqualTo(50);
  }

  @Test
  @DisplayName("PG-4 非法边界配置（min<1 或 max<min）显式拒绝")
  void rejectsInvalidBounds() {
    assertThatThrownBy(() -> PageRequests.bounded(0, 10, 0, 100, Sort.unsorted()))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> PageRequests.bounded(0, 10, 100, 50, Sort.unsorted()))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  @DisplayName("PG-5 firstPage 永远不超过全局 MAX_PAGE_SIZE")
  void firstPageRespectsGlobalMaximum() {
    PageRequest request = PageRequests.firstPage(Sort.unsorted());
    assertThat(request.getPageNumber()).isZero();
    assertThat(request.getPageSize()).isEqualTo(PageRequests.MAX_PAGE_SIZE);
  }
}