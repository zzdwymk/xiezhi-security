package com.bachelor.toolbox.recon;

import static org.assertj.core.api.Assertions.assertThat;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SubdomainDictionaryPaginationBoundaryTests {
  @TempDir Path temporary;

  private SubdomainDictionaryController controller() throws Exception {
    Path file = temporary.resolve("subdomains.txt");
    Files.writeString(file, "alpha\nbeta\n");
    SubdomainDictionaryService service = new SubdomainDictionaryService(file.toString());
    service.load();
    return new SubdomainDictionaryController(service);
  }

  @Test
  void maximumPageReturnsEmptyWithoutNegativeOffset() throws Exception {
    var page = controller().words(null, Integer.MAX_VALUE, 1000);
    assertThat(page.words()).isEmpty();
    assertThat(page.total()).isEqualTo(2);
  }

  @Test
  void invalidSmallPageAndSizeClampWithoutLosingFirstWord() throws Exception {
    var page = controller().words(null, 0, -1);
    assertThat(page.page()).isEqualTo(1);
    assertThat(page.size()).isEqualTo(1);
    assertThat(page.words()).containsExactly("alpha");
  }
}
