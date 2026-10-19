package com.bachelor.toolbox.recon;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.bachelor.toolbox.common.ApiException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Dictionary-library behaviour.
 *
 * <p>Semantic change from the single-wordlist era: {@link PathDictionaryService#currentWords()}
 * now returns the <em>default shipped</em> dictionary (dirb common), and the administrator-managed
 * list is a separate {@code custom} dictionary in the library. Tests that used to assert "import
 * then currentWords()" now assert against {@code custom}.
 */
class PathDictionaryServiceTest {
  @TempDir Path tempDir;

  private PathDictionaryService newService(Path dir) {
    return new PathDictionaryService(
        dir.resolve("web-paths.txt").toString(),
        dir.resolve("dictionaries").toString(),
        PathDictionaryService.DEFAULT_DICTIONARY_ID);
  }

  private PathDictionaryService loadedService(Path dir) {
    PathDictionaryService service = newService(dir);
    service.load();
    return service;
  }

  @Test
  void shipsTheWellKnownDictionariesWithRealEntryCounts() {
    PathDictionaryService service = loadedService(tempDir);
    var library = service.library();
    assertThat(library).extracting(PathDictionaryService.DictionaryView::id)
        .contains("dirb-common", "dirb-big", "dirb-small", "dirb-best1050", "dirbuster-2.3-small");
    var common =
        library.stream()
            .filter(view -> "dirb-common".equals(view.id()))
            .findFirst()
            .orElseThrow();
    // dirb common is ~4.6k entries; the previous built-in list had 38.
    assertThat(common.entryCount()).isGreaterThan(4_000);
    assertThat(common.source()).isEqualTo("BUILTIN");
  }

  @Test
  void defaultDictionaryIsDirbCommonAndHasThousandsOfEntries() {
    PathDictionaryService service = loadedService(tempDir);
    assertThat(service.defaultDictionaryId()).isEqualTo("dirb-common");
    assertThat(service.currentWords()).hasSizeGreaterThan(4_000);
  }

  @Test
  void unknownDictionaryFallsBackToTheDefaultInsteadOfFailing() {
    PathDictionaryService service = loadedService(tempDir);
    assertThat(service.resolveId("does-not-exist")).isEqualTo("dirb-common");
    assertThat(service.words("does-not-exist")).isNotEmpty();
  }

  @Test
  void customDictionaryStartsEmptyAndIsListedOnlyAfterImport() {
    PathDictionaryService service = loadedService(tempDir);
    assertThat(service.library()).extracting(PathDictionaryService.DictionaryView::id)
        .doesNotContain("custom");

    PathDictionaryService.ImportResult result =
        service.importText("# comment\nadmin/\napi/v1/\nadmin/\nbad path\n..\n\n");
    assertThat(result.imported()).isEqualTo(2);
    assertThat(result.duplicates()).isEqualTo(1);
    assertThat(result.invalid()).isEqualTo(2);
    assertThat(Files.exists(tempDir.resolve("web-paths.txt"))).isTrue();
    assertThat(service.library()).extracting(PathDictionaryService.DictionaryView::id)
        .contains("custom");
    assertThat(service.words("custom")).containsExactly("admin/", "api/v1/");
  }

  @Test
  void importingIntoCustomDoesNotMutateTheDefaultDictionary() {
    PathDictionaryService service = loadedService(tempDir);
    int defaultBefore = service.currentWords().size();
    service.importText("zzz-only-in-custom/\n");
    assertThat(service.currentWords()).hasSize(defaultBefore);
    assertThat(service.words("custom")).containsExactly("zzz-only-in-custom/");
  }

  @Test
  void updateAddsAndRemovesWithinCustomAndPersistsAcrossReload() {
    PathDictionaryService service = loadedService(tempDir);
    service.importText("admin/\nlogin/\n");
    PathDictionaryService.UpdateResult result =
        service.update(java.util.List.of("backup/", "ADMIN/"), java.util.Set.of("login/"));
    assertThat(result.added()).isEqualTo(1);
    assertThat(result.removed()).isEqualTo(1);
    assertThat(service.words("custom")).containsExactly("admin/", "backup/");

    PathDictionaryService reloaded = loadedService(tempDir);
    assertThat(reloaded.words("custom")).containsExactly("admin/", "backup/");
  }

  @Test
  void updateReportsMissingRemovals() {
    PathDictionaryService service = loadedService(tempDir);
    service.importText("admin/\nlogin/\n");
    PathDictionaryService.UpdateResult result =
        service.update(java.util.List.of(), java.util.Set.of("login/", "ghost/"));
    assertThat(result.removed()).isEqualTo(1);
    assertThat(result.missing()).containsExactly("ghost/");
  }

  @Test
  void validateWordAllowsPathCharactersAndRejectsSpacesTraversalAndHash() {
    PathDictionaryService service = loadedService(tempDir);
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
    PathDictionaryService service = loadedService(tempDir);
    assertThatThrownBy(() -> service.update(java.util.List.of("has space"), java.util.Set.of()))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("无效词条");
  }

  @Test
  void paginatesAndFiltersANamedDictionary() {
    PathDictionaryService service = loadedService(tempDir);
    PathDictionaryService.WordPage page = service.pageWords("dirb-common", "admin", 1, 10);
    assertThat(page.words()).isNotEmpty();
    assertThat(page.words()).allMatch(word -> word.contains("admin"));
    assertThat(page.total()).isGreaterThan(0);
  }
}
