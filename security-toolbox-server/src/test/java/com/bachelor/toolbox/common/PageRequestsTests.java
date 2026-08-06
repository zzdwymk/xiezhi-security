package com.bachelor.toolbox.common;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;
import org.springframework.data.domain.Sort;

class PageRequestsTests {
  private static final Sort CREATED_AT_DESC = Sort.by(Sort.Direction.DESC, "createdAt");

  @Test
  void clampsNegativePageAndOversizedPageSize() {
    var request = PageRequests.bounded(-2, 999, 1, 100, CREATED_AT_DESC);

    assertEquals(0, request.getPageNumber());
    assertEquals(100, request.getPageSize());
    assertEquals(CREATED_AT_DESC, request.getSort());
  }

  @Test
  void enforcesMinimumPageSize() {
    var request = PageRequests.bounded(3, 0, 10, 100, CREATED_AT_DESC);

    assertEquals(3, request.getPageNumber());
    assertEquals(10, request.getPageSize());
  }

  @Test
  void firstPageUsesTheSharedMaximumPageSize() {
    var request = PageRequests.firstPage(CREATED_AT_DESC);

    assertEquals(0, request.getPageNumber());
    assertEquals(PageRequests.MAX_PAGE_SIZE, request.getPageSize());
    assertEquals(CREATED_AT_DESC, request.getSort());
  }

  @Test
  void rejectsInvalidBounds() {
    assertThrows(
        IllegalArgumentException.class, () -> PageRequests.bounded(0, 20, 50, 10, CREATED_AT_DESC));
  }
}
