package com.bachelor.toolbox.recon;

import com.bachelor.toolbox.common.ApiException;
import jakarta.annotation.PostConstruct;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;

/**
 * Web path scan dictionary library.
 *
 * <p>The platform ships several well-known community dictionaries as classpath resources under
 * {@code wordlists/dirscan/} (dirb, dirbuster). Each shipped dictionary is one selectable
 * "dictionary", and the operator may additionally register external dictionary files by placing
 * them in the configured {@code external-dictionary-dir}.
 *
 * <p>This replaces the earlier single-wordlist model (a 38-line built-in list) which made active
 * path enumeration effectively useless on real targets.
 *
 * <h2>Design notes</h2>
 *
 * <ul>
 *   <li>Dictionaries are loaded lazily and cached; entry counts are resolved once at startup so the
 *       UI can show "dirb common (4613)" without reading 900 KB on every request.
 *   <li>An administrator may still maintain a <em>managed</em> custom dictionary persisted to
 *       {@code toolbox.recon.path-dictionary-file}. It appears in the library as {@code custom}.
 *   <li>{@link #currentWords()} keeps the legacy contract: it returns the default dictionary's
 *       words, so existing callers (recon collection) keep working unchanged.
 * </ul>
 */
@Service
public class PathDictionaryService {
  private static final Logger log = LoggerFactory.getLogger(PathDictionaryService.class);

  /** classpath prefix holding the shipped dictionaries. */
  private static final String BUILTIN_PREFIX = "wordlists/dirscan/";

  /** Shipped dictionaries: stable id -> [display name, classpath file, description]. */
  private static final Map<String, ShippedDictionary> SHIPPED = shippedDictionaries();

  /** Default dictionary used when the caller does not name one. */
  public static final String DEFAULT_DICTIONARY_ID = "dirb-common";

  /** Id of the administrator-managed dictionary (target of import/update/replace). */
  public static final String CUSTOM_DICTIONARY_ID = "custom";

  private static final int MAX_WORDS = 100_000;
  private static final Pattern PATH_WORD = Pattern.compile("[A-Za-z0-9._/\\[\\]-]{1,255}");

  private final Path managedFile;
  private final Path externalDir;
  private final String defaultDictionaryId;

  /** id -> words, populated on first use. */
  private final Map<String, List<String>> cache = new LinkedHashMap<>();

  /** id -> metadata, populated at startup for the shipped dictionaries only. */
  private final Map<String, DictionaryView> views = new LinkedHashMap<>();

  public PathDictionaryService(
      @Value("${toolbox.recon.path-dictionary-file:./data/recon/web-paths.txt}")
          String managedFile,
      @Value("${toolbox.recon.external-dictionary-dir:./data/recon/dictionaries}")
          String externalDir,
      @Value("${toolbox.recon.default-path-dictionary:" + DEFAULT_DICTIONARY_ID + "}")
          String defaultDictionaryId) {
    this.managedFile = Path.of(managedFile).toAbsolutePath().normalize();
    this.externalDir = Path.of(externalDir).toAbsolutePath().normalize();
    String wanted = defaultDictionaryId == null ? "" : defaultDictionaryId.trim();
    this.defaultDictionaryId =
        SHIPPED.containsKey(wanted) || CUSTOM_DICTIONARY_ID.equals(wanted)
            ? wanted
            : DEFAULT_DICTIONARY_ID;
  }

  @PostConstruct
  void load() {
    synchronized (cache) {
      // Only the entry count is needed at startup: read each shipped file's raw text once to get an
      // accurate count, then keep the parsed list so the first scan does not pay the parse cost twice.
      SHIPPED.forEach(
          (id, shipped) -> {
            try {
              List<String> words = parseAndDedupe(readClasspath(shipped.resource()));
              if (words.isEmpty()) {
                log.warn("内置字典为空，已跳过：{} ({})", shipped.displayName(), shipped.resource());
                return;
              }
              cache.put(id, words);
              views.put(
                  id,
                  new DictionaryView(id, shipped.displayName(), "BUILTIN", words.size(), shipped.description()));
            } catch (IOException | RuntimeException ex) {
              log.warn("加载内置字典失败 {}: {}", shipped.resource(), ex.getMessage());
            }
          });
      if (Files.isRegularFile(managedFile, LinkOption.NOFOLLOW_LINKS)) {
        try {
          List<String> words = parseAndDedupe(Files.readString(managedFile, StandardCharsets.UTF_8));
          cache.put(CUSTOM_DICTIONARY_ID, words);
          views.put(CUSTOM_DICTIONARY_ID, new DictionaryView(CUSTOM_DICTIONARY_ID, "自定义字典", "MANAGED", words.size(), "管理员维护的路径字典"));
        } catch (IOException ex) {
          log.warn("读取托管路径词典失败：{}", ex.getMessage());
        }
      }
      log.info(
          "路径字典库已加载：{} 本，默认 {}",
          views.size(),
          views.containsKey(defaultDictionaryId) ? defaultDictionaryId : "（无）");
    }
  }

  /** Dictionary library for the management UI (metadata only, no word lists). */
  public List<DictionaryView> library() {
    synchronized (cache) {
      refreshExternalViews();
      return List.copyOf(views.values());
    }
  }

  /** Returns the configured default dictionary id (may be absent from the library). */
  public String defaultDictionaryId() {
    return defaultDictionaryId;
  }

  /**
   * Resolves a dictionary id, falling back to the default when the id is blank or unknown.
   *
   * <p>{@code custom} is always resolvable even before the managed file exists: it is the target of
   * the management operations ({@code importText} / {@code update} / {@code replace}), so treating
   * "custom" as unknown would make the first import seed itself with the default dictionary.
   *
   * <p>Other unknown ids fall back rather than failing: a saved scan configuration that names a
   * dictionary the operator later deleted must still run, with an explicit evidence note rather than
   * a crash.
   */
  public String resolveId(String requestedId) {
    if (requestedId == null || requestedId.isBlank()) {
      return defaultDictionaryId;
    }
    String id = requestedId.trim();
    if (CUSTOM_DICTIONARY_ID.equals(id)) {
      return CUSTOM_DICTIONARY_ID;
    }
    synchronized (cache) {
      if (views.containsKey(id)) {
        return id;
      }
      refreshExternalViews();
      if (views.containsKey(id)) {
        return id;
      }
    }
    log.warn("未知路径字典 {}，回退默认 {}", id, defaultDictionaryId);
    return defaultDictionaryId;
  }

  /** Returns the words of the given dictionary (resolved, deduplicated, ordered). */
  public List<String> words(String requestedId) {
    String id = resolveId(requestedId);
    synchronized (cache) {
      List<String> cached = cache.get(id);
      if (cached != null) {
        return cached;
      }
      List<String> loaded = loadDictionary(id);
      cache.put(id, loaded);
      DictionaryView view = views.get(id);
      if (view != null) {
        views.put(id, new DictionaryView(id, view.displayName(), view.source(), loaded.size(), view.description()));
      }
      return loaded;
    }
  }

  /** Legacy accessor: words of the default dictionary. */
  public List<String> currentWords() {
    return words(null);
  }

  /** Legacy accessor: view of the default dictionary. */
  public DictionaryView view() {
    String id = resolveId(null);
    synchronized (cache) {
      DictionaryView view = views.get(id);
      return view == null ? new DictionaryView(id, id, "MISSING", 0, "") : view;
    }
  }

  /** Returns a filtered, paginated slice of the default dictionary's words. */
  public WordPage pageWords(String query, int page, int size) {
    return pageWords(null, query, page, size);
  }

  /** Returns a filtered, paginated slice of the given dictionary's words. */
  public WordPage pageWords(String dictionaryId, String query, int page, int size) {
    int safePage = Math.max(page, 1);
    int safeSize = Math.max(1, Math.min(size, 1_000));
    List<String> all = words(dictionaryId);
    if (query != null && !query.isBlank()) {
      String needle = query.trim().toLowerCase(Locale.ROOT);
      all = all.stream().filter(word -> word.contains(needle)).toList();
    }
    int total = all.size();
    int from = (safePage - 1) * safeSize;
    if (from >= total) {
      return new WordPage(List.of(), safePage, safeSize, total);
    }
    int to = Math.min(from + safeSize, total);
    return new WordPage(all.subList(from, to), safePage, safeSize, total);
  }

  /** Validates a single path word; returns null when valid, otherwise a human-readable reason. */
  public String validateWord(String word) {
    if (word == null || word.isBlank()) {
      return "词条不能为空";
    }
    String trimmed = word.trim();
    if (trimmed.contains(" ") || trimmed.contains("#")) {
      return "词条不能包含空格或 #";
    }
    if (trimmed.contains("..")) {
      return "词条不能包含 ..";
    }
    if (!PATH_WORD.matcher(trimmed).matches()) {
      return "仅允许字母、数字及 . _ / [ ] - 等路径字符（1-255 位）";
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
   * Parses a raw multi-line text and merges it into the managed custom dictionary, reporting how
   * many entries were imported, skipped as invalid, or already present.
   */
  public ImportResult importText(String text) {
    List<String> incoming = parseLines(text);
    if (incoming.size() > MAX_WORDS) {
      throw new ApiException("一次导入的词条数量超过 100000 条限制");
    }
    Set<String> current = new LinkedHashSet<>(words(CUSTOM_DICTIONARY_ID));
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
      String word = raw.trim().toLowerCase(Locale.ROOT);
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
      putCustom(merged);
    }
    List<String> invalidList = new ArrayList<>(invalidEcho);
    return new ImportResult(imported, invalid, duplicates, invalidList);
  }

  /** Adds or removes words in the managed custom dictionary and persists the result. */
  public UpdateResult update(List<String> additions, Set<String> removals) {
    Set<String> current = new LinkedHashSet<>(words(CUSTOM_DICTIONARY_ID));
    int added = 0;
    int removed = 0;
    Set<String> missing = new LinkedHashSet<>();
    if (additions != null) {
      for (String raw : additions) {
        String problem = validateWord(raw);
        if (problem != null) {
          throw new ApiException("无效词条 " + raw.trim() + "：" + problem);
        }
        if (current.add(raw.trim().toLowerCase(Locale.ROOT))) {
          added++;
        }
      }
    }
    if (removals != null) {
      for (String raw : removals) {
        String word = raw.trim().toLowerCase(Locale.ROOT);
        if (current.remove(word)) {
          removed++;
        } else {
          missing.add(word);
        }
      }
    }
    if (added > 0 || removed > 0) {
      List<String> merged = new ArrayList<>(current);
      persist(merged);
      putCustom(merged);
    }
    return new UpdateResult(view(CUSTOM_DICTIONARY_ID), added, removed, List.copyOf(missing));
  }

  /** Replaces the managed custom dictionary with the given words. */
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
      cleaned.add(raw.trim().toLowerCase(Locale.ROOT));
    }
    List<String> merged = new ArrayList<>(cleaned);
    persist(merged);
    putCustom(merged);
    return new UpdateResult(view(CUSTOM_DICTIONARY_ID), merged.size(), 0, List.of());
  }

  public List<String> parseLines(String text) {
    if (text == null) {
      return List.of();
    }
    return java.util.Arrays.stream(text.split("\\R"))
        .map(String::trim)
        .filter(value -> !value.isEmpty() && !value.startsWith("#"))
        .toList();
  }

  // ---------------------------------------------------------------- internals

  private DictionaryView view(String id) {
    synchronized (cache) {
      DictionaryView found = views.get(id);
      return found == null ? new DictionaryView(id, id, "MISSING", 0, "") : found;
    }
  }

  private void putCustom(List<String> words) {
    synchronized (cache) {
      cache.put(CUSTOM_DICTIONARY_ID, words);
      views.put(CUSTOM_DICTIONARY_ID, new DictionaryView(CUSTOM_DICTIONARY_ID, "自定义字典", "MANAGED", words.size(), "管理员维护的路径字典"));
    }
  }

  private List<String> loadDictionary(String id) {
    ShippedDictionary shipped = SHIPPED.get(id);
    if (shipped != null) {
      try {
        return parseAndDedupe(readClasspath(shipped.resource()));
      } catch (IOException | RuntimeException ex) {
        log.warn("加载内置字典失败 {}: {}", shipped.resource(), ex.getMessage());
        return List.of();
      }
    }
    if (CUSTOM_DICTIONARY_ID.equals(id)) {
      if (Files.isRegularFile(managedFile, LinkOption.NOFOLLOW_LINKS)) {
        try {
          return parseAndDedupe(Files.readString(managedFile, StandardCharsets.UTF_8));
        } catch (IOException ex) {
          log.warn("读取托管路径词典失败：{}", ex.getMessage());
        }
      }
      return List.of();
    }
    // External dictionary registered from the configured directory.
    Path external = externalFile(id);
    if (external != null) {
      try {
        return parseAndDedupe(Files.readString(external, StandardCharsets.UTF_8));
      } catch (IOException ex) {
        log.warn("读取外部路径字典失败 {}: {}", external, ex.getMessage());
      }
    }
    return List.of();
  }

  /** Registers (metadata only) dictionary files found in the configured external directory. */
  private void refreshExternalViews() {
    if (!Files.isDirectory(externalDir)) {
      return;
    }
    try (var stream = Files.list(externalDir)) {
      stream
          .filter(path -> Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS))
          .filter(path -> path.getFileName().toString().toLowerCase(Locale.ROOT).endsWith(".txt"))
          .sorted()
          .forEach(
              path -> {
                String fileName = path.getFileName().toString();
                String id = "ext:" + fileName;
                if (views.containsKey(id)) {
                  return;
                }
                views.put(
                    id,
                    new DictionaryView(id, fileName, "EXTERNAL", -1, "外部字典目录中的词表"));
              });
    } catch (IOException ex) {
      log.debug("扫描外部字典目录失败 {}: {}", externalDir, ex.getMessage());
    }
  }

  private Path externalFile(String id) {
    if (id == null || !id.startsWith("ext:")) {
      return null;
    }
    String fileName = id.substring("ext:".length());
    if (fileName.contains("..") || fileName.contains("/") || fileName.contains("\\")) {
      return null;
    }
    Path candidate = externalDir.resolve(fileName).normalize();
    if (!candidate.startsWith(externalDir)) {
      return null;
    }
    return Files.isRegularFile(candidate, LinkOption.NOFOLLOW_LINKS) ? candidate : null;
  }

  private String readClasspath(String resource) throws IOException {
    ClassPathResource classPathResource = new ClassPathResource(resource);
    if (!classPathResource.exists()) {
      throw new IOException("classpath 资源不存在: " + resource);
    }
    try (InputStream input = classPathResource.getInputStream()) {
      return new String(input.readAllBytes(), StandardCharsets.UTF_8);
    }
  }

  private List<String> parseAndDedupe(String text) {
    Set<String> set = new LinkedHashSet<>();
    for (String line : text.split("\\R")) {
      String word = line.trim().toLowerCase(Locale.ROOT);
      if (word.isEmpty() || word.startsWith("#")) {
        continue;
      }
      // dirb / dirbuster lists occasionally carry trailing comments and Windows-only entries; keep
      // only what the scan engine can actually request, so the reported count equals the real budget.
      if (PATH_WORD.matcher(word).matches()) {
        set.add(word);
      }
      if (set.size() >= MAX_WORDS) {
        break;
      }
    }
    return List.copyOf(set);
  }

  private void persist(List<String> value) {
    Path parent = managedFile.getParent();
    if (parent == null) {
      throw new ApiException("路径词典目录无效");
    }
    try {
      Files.createDirectories(parent);
      Path temporary = Files.createTempFile(parent, ".web-paths-", ".txt.tmp");
      boolean moved = false;
      try {
        StringBuilder builder = new StringBuilder("# Xiezhi managed web path dictionary\n");
        for (String word : value) {
          builder.append(word).append('\n');
        }
        Files.writeString(
            temporary,
            builder.toString(),
            StandardCharsets.UTF_8,
            java.nio.file.StandardOpenOption.TRUNCATE_EXISTING,
            java.nio.file.StandardOpenOption.WRITE);
        moveReplacing(temporary);
        moved = true;
      } finally {
        if (!moved) {
          Files.deleteIfExists(temporary);
        }
      }
    } catch (IOException ex) {
      log.error("写路径词典失败：{}", ex.getMessage());
      throw new ApiException("路径词典保存失败");
    }
  }

  private void moveReplacing(Path temporary) throws IOException {
    try {
      Files.move(
          temporary, managedFile, java.nio.file.StandardCopyOption.ATOMIC_MOVE,
          java.nio.file.StandardCopyOption.REPLACE_EXISTING);
    } catch (java.nio.file.AtomicMoveNotSupportedException ex) {
      Files.move(temporary, managedFile, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
    }
  }

  private static Map<String, ShippedDictionary> shippedDictionaries() {
    Map<String, ShippedDictionary> map = new LinkedHashMap<>();
    map.put(
        "dirb-common",
        new ShippedDictionary(
            "dirb common",
            BUILTIN_PREFIX + "dirb-common.txt",
            "dirb 默认字典，覆盖常见管理后台、备份、配置文件，速度与命中率平衡"));
    map.put(
        "dirb-big",
        new ShippedDictionary(
            "dirb big",
            BUILTIN_PREFIX + "dirb-big.txt",
            "dirb 大字典，条目更多，完整扫描耗时更长"));
    map.put(
        "dirb-small",
        new ShippedDictionary(
            "dirb small", BUILTIN_PREFIX + "dirb-small.txt", "dirb 精简字典，用于快速探测"));
    map.put(
        "dirb-best1050",
        new ShippedDictionary(
            "dirb best1050",
            BUILTIN_PREFIX + "dirb-best1050.txt",
            "dirb 精选字典，命中率与耗时折中"));
    map.put(
        "dirbuster-2.3-small",
        new ShippedDictionary(
            "dirbuster 2.3 small",
            BUILTIN_PREFIX + "dirbuster-2.3-small.txt",
            "dirbuster 2.3 小字典，条目最多，适合充分授权且时间充裕的评估"));
    return Map.copyOf(map);
  }

  private record ShippedDictionary(String displayName, String resource, String description) {}

  /**
   * Metadata for one dictionary.
   *
   * @param entryCount number of usable entries; {@code -1} when not yet resolved
   */
  public record DictionaryView(
      String id, String displayName, String source, int entryCount, String description) {}

  public record WordPage(List<String> words, int page, int size, int total) {}

  public record ImportResult(int imported, int invalid, int duplicates, List<String> issues) {}

  public record UpdateResult(DictionaryView view, int added, int removed, List<String> missing) {}
}
