package com.bachelor.toolbox.recon;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.bachelor.toolbox.common.ApiException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SubdomainDictionaryServiceTest {
  @TempDir Path tempDir;

  private SubdomainDictionaryService newService(Path dir) {
    return new SubdomainDictionaryService(dir.resolve("subdomains.txt").toString());
  }

  @Test
  void reportsBuiltinSourceUntilManagedFileCreated() {
    SubdomainDictionaryService service = newService(tempDir);
    assertThat(service.view().source()).isEqualTo("BUILTIN");
  }

  @Test
  void importsDeduplicatesAndIgnoresCommentsAndInvalidWords() {
    SubdomainDictionaryService service = newService(tempDir);
    SubdomainDictionaryService.ImportResult result =
        service.importText("# comment\nwww\napi\nwww\nbad.word\n-ok-\n\n");
    assertThat(result.imported()).isEqualTo(3);
    assertThat(result.duplicates()).isEqualTo(1);
    assertThat(result.invalid()).isEqualTo(1);
    assertThat(result.issues()).singleElement().satisfies(
        issue -> assertThat(issue).startsWith("bad.word"));
    assertThat(Files.exists(tempDir.resolve("subdomains.txt"))).isTrue();
    assertThat(service.view().source()).isEqualTo("MANAGED");
    assertThat(service.currentWords()).containsExactlyInAnyOrder("www", "api", "-ok-");
  }

  @Test
  void updateAddsAndRemovesAndPersists() {
    SubdomainDictionaryService service = newService(tempDir);
    service.importText("alpha\nbeta\n");
    SubdomainDictionaryService.UpdateResult result =
        service.update(java.util.List.of("gamma", "ALPHA"), java.util.Set.of("beta"));
    assertThat(result.added()).isEqualTo(1); // gamma new; ALPHA dedupes to existing alpha
    assertThat(result.removed()).isEqualTo(1);
    assertThat(service.currentWords()).containsExactly("alpha", "gamma");
    // Reload from disk to confirm persistence (service reads the managed file).
    SubdomainDictionaryService reloaded = newService(tempDir);
    reloaded.load();
    assertThat(reloaded.currentWords()).containsExactly("alpha", "gamma");
  }

  @Test
  void rejectsInvalidAdditionsInUpdate() {
    SubdomainDictionaryService service = newService(tempDir);
    assertThatThrownBy(() -> service.update(java.util.List.of("has space"), java.util.Set.of()))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("无效词条");
  }

  @Test
  void replaceReplacesWholeDictionary() {
    SubdomainDictionaryService service = newService(tempDir);
    service.importText("alpha\nbeta\n");
    service.replace(java.util.List.of("gamma", "delta"));
    assertThat(service.currentWords()).containsExactly("gamma", "delta");
  }

  @Test
  void validateWordRejectsDotSpaceAndWrongChars() {
    SubdomainDictionaryService service = newService(tempDir);
    assertThat(service.validateWord("www.example")).isNotNull();
    assertThat(service.validateWord("has space")).isNotNull();
    assertThat(service.validateWord("bad_underscore")).isNotNull();
    assertThat(service.validateWord("")).isNotNull();
    assertThat(service.validateWord("valid-123")).isNull();
  }

  @Test
  void validateWordRejectsPureNumericButKeepsMixedLabels() {
    SubdomainDictionaryService service = newService(tempDir);
    assertThat(service.validateWord("123")).isNotNull();
    assertThat(service.validateWord("000123")).isNotNull();
    assertThat(service.validateWord("1st")).isNull();
    assertThat(service.validateWord("b2b")).isNull();
    assertThat(service.validateWord("3g")).isNull();
  }

  @Test
  void updateReportsMissingRemovals() {
    SubdomainDictionaryService service = newService(tempDir);
    service.importText("alpha\nbeta\n");
    SubdomainDictionaryService.UpdateResult result =
        service.update(java.util.List.of(), java.util.Set.of("beta", "ghost"));
    assertThat(result.removed()).isEqualTo(1);
    assertThat(result.missing()).containsExactly("ghost");
  }

  @Test
  void importAndLoadIgnorePureNumericWords() {
    SubdomainDictionaryService service = newService(tempDir);
    SubdomainDictionaryService.ImportResult result =
        service.importText("www\n123\n000123\napi\n");
    assertThat(result.imported()).isEqualTo(2);
    assertThat(result.invalid()).isEqualTo(2);
    assertThat(service.currentWords()).containsExactly("www", "api");
  }
}