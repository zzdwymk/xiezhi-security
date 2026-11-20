package com.bachelor.toolbox.recon;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Round 234：外部/托管路径字典必须限制单文件字节数。 */
class PathDictionaryExternalSizeTests {

  @TempDir Path temp;

  @Test
  void oversizedExternalDictionaryIsNotLoaded() throws Exception {
    Path managed = temp.resolve("managed.txt");
    Files.writeString(managed, "admin\n", StandardCharsets.UTF_8);
    Path external = Files.createDirectory(temp.resolve("external"));
    Path big = external.resolve("big.txt");
    try (var out = Files.newOutputStream(big)) {
      byte[] chunk = "a\n".repeat(1024).getBytes(StandardCharsets.UTF_8);
      for (int i = 0; i < 4097; i++) out.write(chunk); // just over the 8 MiB cap
    }

    PathDictionaryService service =
        new PathDictionaryService(managed.toString(), external.toString(), "custom");
    var page = service.pageWords("ext:big.txt", null, 1, 30);
    assertThat(page.total()).isZero();
    assertThat(page.words()).isEmpty();
  }

  @Test
  void normalExternalDictionaryStillLoads() throws Exception {
    Path managed = temp.resolve("managed.txt");
    Files.writeString(managed, "admin\n", StandardCharsets.UTF_8);
    Path external = Files.createDirectory(temp.resolve("external"));
    Files.writeString(external.resolve("small.txt"), "admin\nlogin\n", StandardCharsets.UTF_8);

    PathDictionaryService service =
        new PathDictionaryService(managed.toString(), external.toString(), "custom");
    var page = service.pageWords("ext:small.txt", null, 1, 30);
    assertThat(page.total()).isEqualTo(2);
    assertThat(page.words()).containsExactly("admin", "login");
  }
}
