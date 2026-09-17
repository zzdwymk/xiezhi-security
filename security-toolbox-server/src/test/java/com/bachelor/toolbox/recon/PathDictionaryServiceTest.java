package com.bachelor.toolbox.recon;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.bachelor.toolbox.common.ApiException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class PathDictionaryServiceTest {
  @TempDir Path tempDir;

  private PathDictionaryService newService(Path dir) {
    return new PathDictionaryService(dir.resolve("web-paths.txt").toString());
  }

  @Test
  void reportsBuiltinSourceUntilManagedFileCreated() {
    PathDictionaryService service = newService(tempDir);
    assertThat(service.view().source()).isEqualTo("BUILTIN");
  }

  @Test
  void importsDeduplicatesAndIgnoresCommentsAndInvalidWords() {
    PathDictionaryService service = newService(tempDir);
    PathDictionaryService.ImportResult result =
        service.importText("# comment\nadmin/\napi/v1/\nadmin/\nbad path\n..\n\n");
    assertThat(result.imported()).isEqualTo(2);
    assertThat(result.duplicates()).isEqualTo(1);
    assertThat(result.invalid()).isEqualTo(2);
    assertThat(Files.exists(tempDir.resolve("web-paths.txt"))).isTrue();
    assertThat(service.view().source()).isEqualTo("MANAGED");
    assertThat(service.currentWords()).containsExactly("admin/", "api/v1/");
  }

  @Test
  void updateAddsAndRemovesAndPersists() {
    PathDictionaryService service = newService(tempDir);
    service.importText("admin/\nlogin/\n");
    PathDictionaryService.UpdateResult result =
        service.update(java.util.List.of("backup/", "ADMIN/"), java.util.Set.of("login/"));
    assertThat(result.added()).isEqualTo(1);
    assertThat(result.removed()).isEqualTo(1);
    assertThat(service.currentWords()).containsExactly("admin/", "backup/");
    PathDictionaryService reloaded = newService(tempDir);
    reloaded.load();
    assertThat(reloaded.currentWords()).containsExactly("admin/", "backup/");
  }

  @Test
  void updateReportsMissingRemovals() {
    PathDictionaryService service = newService(tempDir);
    service.importText("admin/\nlogin/\n");
    PathDictionaryService.UpdateResult result =
        service.update(java.util.List.of(), java.util.Set.of("login/", "ghost/"));
    assertThat(result.removed()).isEqualTo(1);
    assertThat(result.missing()).containsExactly("ghost/");
  }

  @Test
  void validateWordAllowsPathCharactersAndRejectsSpacesTraversalAndHash() {
    PathDictionaryService service = newService(tempDir);
    assertThat(service.validateWord("api/v1/")).isNull();
    assertThat(service.validateWord("robots.txt")).isNull();
    assertThat(service.validateWord(".env")).isNull();
    assertThat(service.validateWord("Less-[1-65]/")).isNull();
    assertThat(service.validateWord("has space")).isNotNull();
    assertThat(service.validateWord("a..b")).isNotNull();
    assertThat(service.validateWord("bad#frag")).isNotNull();
    assertThat(service.validateWord("")).isNotNull();
  }

  @Test
  void rejectsInvalidAdditionsInUpdate() {
    PathDictionaryService service = newService(tempDir);
    assertThatThrownBy(() -> service.update(java.util.List.of("has space"), java.util.Set.of()))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("无效词条");
  }
}
