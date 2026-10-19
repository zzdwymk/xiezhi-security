package com.bachelor.toolbox.tool;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.asset.DiscoveredPathService;
import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.recon.PathDictionaryService;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.PortRangeParser;
import com.bachelor.toolbox.target.TargetPolicyService;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * {@code dir_scan} behaviour and, more importantly, its authorization invariants.
 *
 * <p>The point of these tests is not "does it find paths" but "does raising concurrency ever let a
 * request escape the authorized host:port boundary". Concurrency is an operator setting, so it is
 * exactly the kind of knob that must not become an authorization lever.
 */
class DirScanToolTests {
  @TempDir Path tempDir;

  private HttpServer server;
  private int port;
  private final ConcurrentLinkedQueue<String> requestedPaths = new ConcurrentLinkedQueue<>();
  private final AtomicInteger requestCount = new AtomicInteger();

  @BeforeEach
  void startServer() throws Exception {
    server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.setExecutor(java.util.concurrent.Executors.newFixedThreadPool(16));
    server.createContext("/", this::handle);
    server.start();
    port = server.getAddress().getPort();
  }

  @AfterEach
  void stopServer() {
    if (server != null) {
      server.stop(0);
    }
  }

  /** Serves a small virtual site: /admin/ exists, /admin/secret.txt exists, everything else 404. */
  private void handle(HttpExchange exchange) throws java.io.IOException {
    String path = exchange.getRequestURI().getPath();
    requestedPaths.add(path);
    requestCount.incrementAndGet();
    String body;
    int status;
    if (path.equals("/admin/") || path.equals("/admin")) {
      status = 200;
      body = "<html><title>Admin console</title>" + "x".repeat(200) + "</html>";
    } else if (path.equals("/admin/secret.txt")) {
      status = 200;
      body = "top secret content that is long enough to differ from the baseline " + "y".repeat(200);
    } else if (path.equals("/login/")) {
      status = 302;
      exchange.getResponseHeaders().add("Location", "/admin/");
      body = "";
    } else {
      // Distinct not-found body so the soft-404 baseline has a stable shape.
      status = 404;
      body = "not found, this path does not exist";
    }
    byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
    exchange.sendResponseHeaders(status, bytes.length == 0 ? -1 : bytes.length);
    if (bytes.length > 0) {
      try (OutputStream output = exchange.getResponseBody()) {
        output.write(bytes);
      }
    }
    exchange.close();
  }

  private AuthorizedTarget target() {
    AuthorizedTarget target = new AuthorizedTarget();
    target.setId(1L);
    target.setEnabled(true);
    target.setTargetValue("http://127.0.0.1:" + port);
    target.setAllowedPorts(String.valueOf(port));
    return target;
  }

  private DirScanTool tool(PathDictionaryService dictionaries, DiscoveredPathService discovered) {
    return new DirScanTool(
        new TargetPolicyService(true, new PortRangeParser()), dictionaries, discovered, 5000);
  }

  private PathDictionaryService dictionariesWith(List<String> words) {
    PathDictionaryService dictionaries = mock(PathDictionaryService.class);
    when(dictionaries.defaultDictionaryId()).thenReturn("test-dict");
    when(dictionaries.resolveId(any())).thenReturn("test-dict");
    when(dictionaries.words(any())).thenReturn(words);
    when(dictionaries.words(anyString())).thenReturn(words);
    return dictionaries;
  }

  private DiscoveredPathService recordingDiscovered() {
    DiscoveredPathService discovered = mock(DiscoveredPathService.class);
    when(discovered.record(any(), anyLong(), anyString(), anyString(), any(), anyLong(), anyString()))
        .thenReturn(true);
    return discovered;
  }

  // ------------------------------------------------------------------ core behaviour

  @Test
  void findsExistingPathsAndSkipsNotFoundOnes() throws Exception {
    DiscoveredPathService discovered = recordingDiscovered();
    DirScanTool tool =
        tool(
            dictionariesWith(List.of("admin/", "admin/secret.txt", "login/", "missing/", "nope/")),
            discovered);

    ToolExecutionResult result =
        tool.execute(target(), Map.of("concurrency", 4, "projectId", 1L));

    @SuppressWarnings("unchecked")
    List<Map<String, Object>> paths = (List<Map<String, Object>>) result.data().get("paths");
    assertThat(paths).extracting(item -> item.get("path")).contains("/admin/", "/admin/secret.txt", "/login/");
    assertThat(paths).extracting(item -> item.get("path")).doesNotContain("/missing/", "/nope/");
    assertThat(result.data()).containsEntry("pathCount", paths.size());
    assertThat(result.summary()).contains("发现");
  }

  @Test
  void recordsTheRedirectInsteadOfFollowingIt() throws Exception {
    DiscoveredPathService discovered = recordingDiscovered();
    DirScanTool tool = tool(dictionariesWith(List.of("login/")), discovered);

    ToolExecutionResult result = tool.execute(target(), Map.of("concurrency", 2, "projectId", 1L));

    @SuppressWarnings("unchecked")
    List<Map<String, Object>> paths = (List<Map<String, Object>>) result.data().get("paths");
    Map<String, Object> login =
        paths.stream().filter(item -> "/login/".equals(item.get("path"))).findFirst().orElseThrow();
    assertThat(login).containsEntry("status", 302);
    assertThat(login).containsEntry("redirect", "/admin/");
    // The redirect target must not have been fetched as a side effect.
    assertThat(requestedPaths).doesNotHaveDuplicates();
  }

  @Test
  void softNotFoundBaselineSuppressesWildcard200s() throws Exception {
    // A SPA-style server that answers 200 with an identical body for every path.
    HttpServer spa = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    spa.createContext(
        "/",
        exchange -> {
          byte[] bytes = "<html><div id=app>loading</div></html>".getBytes(StandardCharsets.UTF_8);
          exchange.sendResponseHeaders(200, bytes.length);
          try (OutputStream output = exchange.getResponseBody()) {
            output.write(bytes);
          }
          exchange.close();
        });
    spa.start();
    try {
      int spaPort = spa.getAddress().getPort();
      AuthorizedTarget spaTarget = new AuthorizedTarget();
      spaTarget.setId(2L);
      spaTarget.setEnabled(true);
      spaTarget.setTargetValue("http://127.0.0.1:" + spaPort);
      spaTarget.setAllowedPorts(String.valueOf(spaPort));
      DirScanTool tool = tool(dictionariesWith(List.of("a/", "b/", "c/")), recordingDiscovered());

      ToolExecutionResult result = tool.execute(spaTarget, Map.of("concurrency", 3));

      assertThat(result.data()).containsEntry("pathCount", 0);
      assertThat(String.valueOf(result.data().get("softNotFound"))).isNotEqualTo("无（基线请求失败）");
    } finally {
      spa.stop(0);
    }
  }

  // ------------------------------------------------------------------ authorization invariants

  @Test
  void highConcurrencyStillStaysInsideTheAuthorizedPort() throws Exception {
    // A second server on a port that is deliberately NOT in the authorized target's port list.
    HttpServer other = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    other.createContext(
        "/",
        exchange -> {
          requestedPaths.add("OUT_OF_SCOPE:" + exchange.getRequestURI().getPath());
          exchange.sendResponseHeaders(200, -1);
          exchange.close();
        });
    other.start();
    try {
      DiscoveredPathService discovered = recordingDiscovered();
      DirScanTool tool =
          tool(dictionariesWith(List.of("admin/", "admin/secret.txt", "x/")), discovered);

      // Maximum allowed concurrency: the operator knob must not widen the reachable surface.
      ToolExecutionResult result =
          tool.execute(
              target(),
              Map.of(
                  "concurrency",
                  DirScanTool.MAX_WORKERS,
                  "depth",
                  1,
                  // An entry that tries to redirect the scan at the other port.
                  "projectId",
                  1L));

      assertThat(result.data()).containsEntry("workers", DirScanTool.MAX_WORKERS);
      assertThat(requestedPaths).noneMatch(path -> path.startsWith("OUT_OF_SCOPE:"));
    } finally {
      other.stop(0);
    }
  }

  @Test
  void concurrencyOutsideOneToFiftyIsRejected() {
    DirScanTool tool = tool(dictionariesWith(List.of("a/")), recordingDiscovered());
    assertThatThrownBy(() -> tool.execute(target(), Map.of("concurrency", 0)))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("并发数");
    assertThatThrownBy(() -> tool.execute(target(), Map.of("concurrency", 51)))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("并发数");
    assertThatThrownBy(() -> tool.execute(target(), Map.of("concurrency", "many")))
        .isInstanceOf(ApiException.class);
  }

  @Test
  void depthOutsideZeroToThreeIsRejected() {
    DirScanTool tool = tool(dictionariesWith(List.of("a/")), recordingDiscovered());
    assertThatThrownBy(() -> tool.execute(target(), Map.of("depth", 4)))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("递归深度");
    assertThatThrownBy(() -> tool.execute(target(), Map.of("depth", -1)))
        .isInstanceOf(ApiException.class);
  }

  // ------------------------------------------------------------------ budget and truncation

  @Test
  void reportsTruncationExplicitlyWhenDictionaryExceedsBudget() throws Exception {
    List<String> big = new java.util.ArrayList<>();
    for (int index = 0; index < 500; index++) {
      big.add("path-" + index + "/");
    }
    List<String> frozen = List.copyOf(big);
    DirScanTool tool = tool(dictionariesWith(frozen), recordingDiscovered());

    ToolExecutionResult result =
        tool.execute(target(), Map.of("concurrency", 8, "maxRequests", 40));

    assertThat(result.data()).containsEntry("dictionaryEntries", 500);
    assertThat(result.data()).containsEntry("plannedRequests", 40);
    assertThat(result.data()).containsEntry("truncated", true);
    assertThat(String.valueOf(result.data().get("truncationNote"))).contains("请求预算");
    assertThat(String.valueOf(result.summary())).contains("截断");
  }

  @Test
  void requestCountNeverExceedsTheBudget() throws Exception {
    List<String> big = new java.util.ArrayList<>();
    for (int index = 0; index < 300; index++) {
      big.add("p" + index + "/");
    }
    List<String> frozen = List.copyOf(big);
    DirScanTool tool = tool(dictionariesWith(frozen), recordingDiscovered());

    ToolExecutionResult result =
        tool.execute(target(), Map.of("concurrency", 20, "maxRequests", 25));

    // Baseline probe + at most the budget.
    assertThat(requestCount.get()).isLessThanOrEqualTo(26);
    assertThat((Integer) result.data().get("requests")).isLessThanOrEqualTo(25);
  }

  @Test
  void doesNotWriteAssetsWhenNoProjectIsSupplied() throws Exception {
    DiscoveredPathService discovered = recordingDiscovered();
    DirScanTool tool = tool(dictionariesWith(List.of("admin/")), discovered);

    ToolExecutionResult result = tool.execute(target(), Map.of("concurrency", 2));

    // The hit is still reported to the caller, it is simply not attached to a project.
    assertThat(result.data()).containsEntry("pathCount", 1);
    org.mockito.Mockito.verify(discovered, org.mockito.Mockito.never())
        .record(any(), anyLong(), anyString(), anyString(), any(), anyLong(), anyString());
  }

  @Test
  void extensionProbingAppendsTheRequestedSuffixes() throws Exception {
    DirScanTool tool = tool(dictionariesWith(List.of("admin")), recordingDiscovered());

    tool.execute(target(), Map.of("concurrency", 2, "extensions", "php,txt"));

    assertThat(requestedPaths).contains("/admin", "/admin.php", "/admin.txt");
  }
}
