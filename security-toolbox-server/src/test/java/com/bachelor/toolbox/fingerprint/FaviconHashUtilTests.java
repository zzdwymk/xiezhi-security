package com.bachelor.toolbox.fingerprint;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class FaviconHashUtilTests {
  @Test
  void calculatesMurmur3AndMd5Correctly() {
    byte[] sampleIco = "sample-favicon-icon-content-data".getBytes(StandardCharsets.UTF_8);

    String murmur3 = FaviconHashUtil.calculateMurmur3(sampleIco);
    String md5 = FaviconHashUtil.calculateMd5(sampleIco);

    assertThat(murmur3).isNotEmpty();
    assertThat(md5).hasSize(32);
    assertThat(md5).matches("^[a-f0-9]{32}$");

    // 空数据保护
    assertThat(FaviconHashUtil.calculateMurmur3(null)).isEmpty();
    assertThat(FaviconHashUtil.calculateMurmur3(new byte[0])).isEmpty();
    assertThat(FaviconHashUtil.calculateMd5(null)).isEmpty();
    assertThat(FaviconHashUtil.calculateMd5(new byte[0])).isEmpty();
  }
}
