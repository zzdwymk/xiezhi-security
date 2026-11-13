package com.bachelor.toolbox.recon;

import java.util.List;
import java.util.Set;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/recon/path-dictionary")
public class PathDictionaryController {
  private final PathDictionaryService dictionary;

  public PathDictionaryController(PathDictionaryService dictionary) {
    this.dictionary = dictionary;
  }

  /** Metadata of the configured default dictionary (legacy shape). */
  @GetMapping
  public PathDictionaryService.DictionaryView view() {
    return dictionary.view();
  }

  /** All selectable dictionaries with entry counts, for the scan options UI. */
  @GetMapping("/library")
  public DictionaryLibraryResponse library() {
    return new DictionaryLibraryResponse(dictionary.defaultDictionaryId(), dictionary.library());
  }

  /** Paginated words of a named dictionary; falls back to the default when {@code dictionaryId} is blank. */
  @GetMapping("/words")
  public PathDictionaryService.WordPage words(
      @RequestParam(name = "dictionary", required = false) String dictionaryId,
      @RequestParam(required = false) String query,
      @RequestParam(defaultValue = "1") int page,
      @RequestParam(defaultValue = "30") int size) {
    return dictionary.pageWords(dictionaryId, query, page, size);
  }

  public record DictionaryLibraryResponse(
      String defaultDictionaryId, List<PathDictionaryService.DictionaryView> dictionaries) {}

  /** Validates a set of words without persisting. Returns a list of offending-word messages. */
  @PostMapping("/validate")
  public Set<String> validate(@jakarta.validation.Valid @RequestBody ValidateRequest request) {
    return dictionary.validateWords(request.words());
  }

  /** Bulk imports words from raw multi-line text; existing/invalid words are reported. */
  @PostMapping("/import")
  public PathDictionaryService.ImportResult importText(@RequestBody TextImportRequest request) {
    return dictionary.importText(request.text());
  }

  /** Adds and/or removes words in one call (the portable editor's save action). */
  @PostMapping("/update")
  public PathDictionaryService.UpdateResult update(@RequestBody UpdateRequest request) {
    return dictionary.update(request.additions(), request.removals());
  }

  public record ValidateRequest(
      // Round 33：限制待校验词条数量，避免超大列表在校验时逐条生成问题串回显（内存放大）。
      @jakarta.validation.constraints.Size(max = 100_000, message = "一次校验的词条数量超过 100000 条限制")
          List<String> words) {}

  public record TextImportRequest(String text) {}

  public record UpdateRequest(List<String> additions, Set<String> removals) {}
}
