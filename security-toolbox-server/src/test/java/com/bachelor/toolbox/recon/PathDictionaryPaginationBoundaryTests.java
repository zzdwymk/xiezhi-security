package com.bachelor.toolbox.recon;

import static org.assertj.core.api.Assertions.assertThat;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class PathDictionaryPaginationBoundaryTests {
  @TempDir Path temporary;

  private PathDictionaryController controller() throws Exception {
    Path file = temporary.resolve("words.txt");
    Files.writeString(file, "alpha\nbeta\n");
    return new PathDictionaryController(new PathDictionaryService(file.toString(), temporary.toString(), "custom"));
  }

  @Test
  void maximumPageMustReturnEmptyWithoutIntegerOverflow() throws Exception {
    var page = controller().words("custom", null, Integer.MAX_VALUE, 1000);
    assertThat(page.words()).isEmpty();
    assertThat(page.total()).isEqualTo(2);
  }

  @Test
  void invalidSmallPageAndSizeClampToOne() throws Exception {
    var page = controller().words("custom", null, 0, -1);
    assertThat(page.page()).isEqualTo(1);
    assertThat(page.size()).isEqualTo(1);
    assertThat(page.words()).containsExactly("alpha");
  }
}
