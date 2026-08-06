package com.bachelor.toolbox.common;

import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;

public final class PageRequests {
  public static final int MAX_PAGE_SIZE = 1000;

  private PageRequests() {}

  public static PageRequest firstPage(Sort sort) {
    return bounded(0, MAX_PAGE_SIZE, 1, MAX_PAGE_SIZE, sort);
  }

  public static PageRequest bounded(
      int page, int size, int minimumSize, int maximumSize, Sort sort) {
    if (minimumSize < 1 || maximumSize < minimumSize) {
      throw new IllegalArgumentException("分页大小边界配置无效");
    }

    int safePage = Math.max(0, page);
    int safeSize = Math.max(minimumSize, Math.min(size, maximumSize));
    return PageRequest.of(safePage, safeSize, sort);
  }
}
