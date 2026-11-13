package com.bachelor.toolbox.common;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.io.StringReader;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * 有界行读取器——Round 17。防止上游无换行超长流导致 {@code readLine()} 内存耗尽（DoS）。
 */
@DisplayName("有界行读取器（Round 17）")
class BoundedLineReaderTest {

  private static BoundedLineReader r(String s, int max) {
    return new BoundedLineReader(new StringReader(s), max);
  }

  @Test
  @DisplayName("BLR-1 正常多行读取（含 \\r\\n 归一）")
  void readsNormalLines() throws IOException {
    BoundedLineReader lines = r("a\r\nb\nc", 100);
    assertThat(lines.readLine()).isEqualTo("a");
    assertThat(lines.readLine()).isEqualTo("b");
    assertThat(lines.readLine()).isEqualTo("c");
    assertThat(lines.readLine()).isNull();
  }

  @Test
  @DisplayName("BLR-2 单行超过上限 → 抛 IOException（不继续增长内存）")
  void overlongLineThrows() {
    String huge = "x".repeat(2048);
    BoundedLineReader lines = r(huge, 1024);
    assertThatThrownBy(lines::readLine).isInstanceOf(IOException.class);
  }

  @Test
  @DisplayName("BLR-3 无换行的超长流（EOF 前一直增长）→ 在上限处抛异常，而非读到 EOF")
  void unboundedNoNewlineStreamAbortsAtLimit() {
    // 5MB 无换行串，上限 1MB：应在读取超过上限时立即失败，不会读满 5MB。
    String huge = "y".repeat(5 * 1024 * 1024);
    BoundedLineReader lines = r(huge, 1024 * 1024);
    assertThatThrownBy(lines::readLine).isInstanceOf(IOException.class);
  }

  @Test
  @DisplayName("BLR-4 空输入返回 null；仅换行返回空行")
  void emptyAndBlankLines() throws IOException {
    assertThat(r("", 10).readLine()).isNull();
    BoundedLineReader lines = r("\n\n", 10);
    assertThat(lines.readLine()).isEmpty();
    assertThat(lines.readLine()).isEmpty();
    assertThat(lines.readLine()).isNull();
  }
}
