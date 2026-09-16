package com.bachelor.toolbox.recon;

import com.bachelor.toolbox.common.ApiException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;

/**
 * Maintains the editable subdomain enumeration dictionary. The managed file becomes authoritative
 * once it exists; until then the built-in classpath wordlist is used, so re-running enumeration
 * always reflects the current dictionary.
 */
@Service
public class SubdomainDictionaryService {
  private static final Logger log = LoggerFactory.getLogger(SubdomainDictionaryService.class);
  private static final String BUILTIN_WORDLIST = "wordlists/subdomains.txt";
  private static final int MAX_WORDS = 100_000;
  private static final Pattern WORD = Pattern.compile("[A-Za-z0-9-]{1,63}");

  private final Path managedFile;
  private volatile List<String> words = List.of();

  public SubdomainDictionaryService(
      @Value("${toolbox.recon.subdomain-dictionary-file:./data/recon/subdomains.txt}")
          String managedFile) {
    this.managedFile = Path.of(managedFile).toAbsolutePath().normalize();
  }

  @PostConstruct
  void load() {
    words = readCurrentWords();
  }

  /** Returns the list of words currently used for enumeration (deduplicated, ordered). */
  public List<String> currentWords() {
    return words;
  }

  /** Returns the current dictionary view for the management UI (metadata only). */
  public DictionaryView view() {
    return new DictionaryView(
        Files.exists(managedFile) ? "MANAGED" : "BUILTIN", words.size());
  }

  /** Returns a filtered, paginated slice of the current dictionary words. */
  public WordPage pageWords(String query, int page, int size) {
    int safePage = Math.max(page, 1);
    int safeSize = Math.max(1, Math.min(size, 1_000));
    List<String> all = words;
    if (query != null && !query.isBlank()) {
      String needle = query.trim().toLowerCase(java.util.Locale.ROOT);
      all = all.stream().filter(w -> w.contains(needle)).toList();
    }
    int total = all.size();
    int from = (safePage - 1) * safeSize;
    if (from >= total) {
      return new WordPage(List.of(), safePage, safeSize, total);
    }
    int to = Math.min(from + safeSize, total);
    return new WordPage(all.subList(from, to), safePage, safeSize, total);
  }

  /** Validates a single word; returns null when valid, otherwise a human-readable reason. */
  public String validateWord(String word) {
    if (word == null || word.isBlank()) {
      return "词条不能为空";
    }
    String trimmed = word.trim();
    if (trimmed.contains(" ") || trimmed.contains(".")) {
      return "词条应为单个子域标签（不含 . 或空格）";
    }
    if (!WORD.matcher(trimmed).matches()) {
      return "仅允许字母、数字和 -（1-63 位）";
    }
    return null;
  }

  /**
   * Validates a batch of words without persisting. Returns a {@code field -> issue} map where the
   * field is the offending word (deduplicated), or an empty map when everything is valid.
   */
  public Set<String> validateWords(List<String> candidates) {
    Set<String> issues = new LinkedHashSet<>();
    if (candidates == null) return issues;
    for (String word : candidates) {
      String problem = validateWord(word);
      if (problem != null) {
        issues.add(word == null ? "<null>" : word.trim() + "：" + problem);
      }
    }
    return issues;
  }

  /**
   * Parses a raw multi-line text (each line one candidate word; {@code #} lines and blanks are
   * ignored) and reports how many were imported, skipped as invalid, and already present.
   */
  public ImportResult importText(String text) {
    List<String> incoming = parseLines(text);
    if (incoming.size() > MAX_WORDS) {
      throw new ApiException("一次导入的词条数量超过 100000 条限制");
    }
    Set<String> current = new LinkedHashSet<>(words);
    int imported = 0;
    int invalid = 0;
    int duplicates = 0;
    Set<String> invalidEcho = new LinkedHashSet<>();
    for (String raw : incoming) {
      String problem = validateWord(raw);
      if (problem != null) {
        invalid++;
        invalidEcho.add(raw.trim() + "：" + problem);
        continue;
      }
      String word = raw.trim().toLowerCase(java.util.Locale.ROOT);
      if (current.contains(word)) {
        duplicates++;
        continue;
      }
      current.add(word);
      imported++;
    }
    if (imported > 0) {
      List<String> merged = new ArrayList<>(current);
      persist(merged);
      words = List.copyOf(merged);
    }
    List<String> invalidList = new ArrayList<>(invalidEcho);
    return new ImportResult(imported, invalid, duplicates, invalidList);
  }

  /** Adds or removes words in bulk and persists the resulting dictionary. */
  public UpdateResult update(List<String> additions, Set<String> removals) {
    Set<String> current = new LinkedHashSet<>(words);
    int added = 0;
    int removed = 0;
    if (additions != null) {
      for (String raw : additions) {
        String problem = validateWord(raw);
        if (problem != null) {
          throw new ApiException("无效词条 " + raw.trim() + "：" + problem);
        }
        if (current.add(raw.trim().toLowerCase(java.util.Locale.ROOT))) {
          added++;
        }
      }
    }
    if (removals != null) {
      for (String raw : removals) {
        if (current.remove(raw.trim().toLowerCase(java.util.Locale.ROOT))) {
          removed++;
        }
      }
    }
    if (added > 0 || removed > 0) {
      List<String> merged = new ArrayList<>(current);
      persist(merged);
      words = List.copyOf(merged);
    }
    return new UpdateResult(view(), added, removed);
  }

  /** Replaces the entire dictionary with the given words (used by the portable editor). */
  public UpdateResult replace(List<String> replacements) {
    if (replacements == null) {
      throw new ApiException("词表不能为空");
    }
    if (replacements.size() > MAX_WORDS) {
      throw new ApiException("词典词条数量超过 100000 条限制");
    }
    Set<String> cleaned = new LinkedHashSet<>();
    for (String raw : replacements) {
      String problem = validateWord(raw);
      if (problem != null) {
        throw new ApiException("无效词条：" + raw.trim() + "：" + problem);
      }
      cleaned.add(raw.trim().toLowerCase(java.util.Locale.ROOT));
    }
    List<String> merged = new ArrayList<>(cleaned);
    persist(merged);
    words = List.copyOf(merged);
    return new UpdateResult(view(), merged.size(), 0);
  }

  public List<String> parseLines(String text) {
    if (text == null) {
      return List.of();
    }
    return java.util.Arrays.stream(text.split("\\R"))
        .map(String::trim)
        .filter(s -> !s.isEmpty() && !s.startsWith("#"))
        .toList();
  }

  private List<String> readCurrentWords() {
    if (Files.isRegularFile(managedFile, LinkOption.NOFOLLOW_LINKS)) {
      try {
        return parseAndDedupe(Files.readString(managedFile, StandardCharsets.UTF_8));
      } catch (IOException ex) {
        log.warn("读取托管子域名词典失败，回退内置字典：{}", ex.getMessage());
      }
    }
    return readBuiltin();
  }

  private List<String> readBuiltin() {
    ClassPathResource resource = new ClassPathResource(BUILTIN_WORDLIST);
    if (!resource.exists()) {
      return List.of();
    }
    try (InputStream input = resource.getInputStream()) {
      return parseAndDedupe(new String(input.readAllBytes(), StandardCharsets.UTF_8));
    } catch (Exception ex) {
      log.debug("加载内置子域名字典失败: {}", ex.getMessage());
      return List.of();
    }
  }

  private List<String> parseAndDedupe(String text) {
    Set<String> set = new LinkedHashSet<>();
    for (String line : text.split("\\R")) {
      String word = line.trim().toLowerCase(java.util.Locale.ROOT);
      if (!word.isEmpty() && !word.startsWith("#") && WORD.matcher(word).matches()) {
        set.add(word);
      }
    }
    return List.copyOf(set);
  }

  private void persist(List<String> value) {
    Path parent = managedFile.getParent();
    if (parent == null) {
      throw new ApiException("子域名词典目录无效");
    }
    try {
      Files.createDirectories(parent);
      Path temporary = Files.createTempFile(parent, ".subdomains-", ".txt.tmp");
      boolean moved = false;
      try {
        StringBuilder sb = new StringBuilder("# Xiezhi managed subdomain dictionary\n");
        for (String word : value) {
          sb.append(word).append('\n');
        }
        Files.writeString(
            temporary,
            sb.toString(),
            StandardCharsets.UTF_8,
            StandardOpenOption.TRUNCATE_EXISTING,
            StandardOpenOption.WRITE);
        moveReplacing(temporary);
        moved = true;
      } finally {
        if (!moved) {
          Files.deleteIfExists(temporary);
        }
      }
    } catch (IOException ex) {
      log.error("写子域名词典失败：{}", ex.getMessage());
      throw new ApiException("子域名词典保存失败");
    }
  }

  private void moveReplacing(Path temporary) throws IOException {
    try {
      Files.move(
          temporary, managedFile, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
    } catch (AtomicMoveNotSupportedException ex) {
      Files.move(temporary, managedFile, StandardCopyOption.REPLACE_EXISTING);
    }
  }

  public record DictionaryView(String source, int wordCount) {}

  public record WordPage(List<String> words, int page, int size, int total) {}

  public record ImportResult(int imported, int invalid, int duplicates, List<String> issues) {}

  public record UpdateResult(DictionaryView view, int added, int removed) {}
}