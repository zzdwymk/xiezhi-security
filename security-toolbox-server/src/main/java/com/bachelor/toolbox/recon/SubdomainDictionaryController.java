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
@RequestMapping("/api/recon/subdomain-dictionary")
public class SubdomainDictionaryController {
  private final SubdomainDictionaryService dictionary;

  public SubdomainDictionaryController(SubdomainDictionaryService dictionary) {
    this.dictionary = dictionary;
  }

  @GetMapping
  public SubdomainDictionaryService.DictionaryView view() {
    return dictionary.view();
  }

  @GetMapping("/words")
  public SubdomainDictionaryService.WordPage words(
      @RequestParam(required = false) String query,
      @RequestParam(defaultValue = "1") int page,
      @RequestParam(defaultValue = "30") int size) {
    return dictionary.pageWords(query, page, size);
  }

  /** Validates a set of words without persisting. Returns a list of offending-word messages. */
  @PostMapping("/validate")
  public Set<String> validate(@RequestBody ValidateRequest request) {
    return dictionary.validateWords(request.words());
  }

  /** Bulk imports words from raw multi-line text; existing/invalid words are reported. */
  @PostMapping("/import")
  public SubdomainDictionaryService.ImportResult importText(@RequestBody TextImportRequest request) {
    return dictionary.importText(request.text());
  }

  /** Adds and/or removes words in one call (the portable editor's save action). */
  @PostMapping("/update")
  public SubdomainDictionaryService.UpdateResult update(@RequestBody UpdateRequest request) {
    return dictionary.update(request.additions(), request.removals());
  }

  public record ValidateRequest(List<String> words) {}

  public record TextImportRequest(String text) {}

  public record UpdateRequest(List<String> additions, Set<String> removals) {}
}