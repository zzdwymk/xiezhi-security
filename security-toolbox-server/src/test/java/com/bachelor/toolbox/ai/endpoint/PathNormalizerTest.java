package com.bachelor.toolbox.ai.endpoint;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

/** {@link PathNormalizer} 的路径规范化（设计文档 §6.5 第三重约束）。 */
class PathNormalizerTest {

  // ------------------------------------------------------------ 合法路径

  @ParameterizedTest
  @ValueSource(
      strings = {
        "/",
        "/api",
        "/api/audits",
        "/api/targets/12/discovered-paths",
        "/api/workflow-runs/9/stop",
        "/api/targets/{targetId}/discovered-paths",
        "/api/vulnerabilities/{id}",
        "/api/ai/agent/graph",
        "/api/findings/1/retest"
      })
  void acceptsWellFormedPathsUnchanged(String path) {
    assertEquals(path, PathNormalizer.normalize(path));
    assertTrue(PathNormalizer.isValid(path));
  }

  @Test
  void acceptsEncodedCharactersThatDoNotChangeRouting() {
    // %20 / %2B 解码后是空格与 +，不会拆出新路径段，因此不构成解析差异；关键是必须原样返回，不能改写。
    assertEquals("/api/a%20b", PathNormalizer.normalize("/api/a%20b"));
    assertEquals("/api/a%2Bb", PathNormalizer.normalize("/api/a%2Bb"));
    assertEquals("/api/%7Bid%7D", PathNormalizer.normalize("/api/%7Bid%7D"));
  }

  // ------------------------------------------------------------ 路径遍历

  @ParameterizedTest
  @ValueSource(
      strings = {
        "/api/../system/shutdown",
        "/api/audits/../../system/shutdown",
        "/../api/audits",
        "/api/..",
        "/..",
        "/api/a/../../../etc/passwd"
      })
  void rejectsPlainDotDotTraversal(String path) {
    assertThrows(PathNormalizer.InvalidEndpointPathException.class, () -> PathNormalizer.normalize(path));
    assertFalse(PathNormalizer.isValid(path));
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "/api/%2e%2e/system/shutdown",
        "/api/%2E%2E/system/shutdown",
        "/api/%2e./system/shutdown",
        "/api/.%2e/system/shutdown",
        "/api/%2e%2e%2f%2e%2e/system",
        "/%2e%2e/api/audits",
        // 双重编码：解码一次得到 %2e%2e，再解码得到 ..
        "/api/%252e%252e/system/shutdown",
        "/api/%25252e%25252e/system/shutdown"
      })
  void rejectsUrlEncodedDotDotTraversal(String path) {
    assertThrows(PathNormalizer.InvalidEndpointPathException.class, () -> PathNormalizer.normalize(path));
    assertFalse(PathNormalizer.isValid(path));
  }

  @Test
  void rejectsMixedEncodedAndLiteralTraversal() {
    assertThrows(
        PathNormalizer.InvalidEndpointPathException.class,
        () -> PathNormalizer.normalize("/api/..%2f..%2fsystem"));
    assertThrows(
        PathNormalizer.InvalidEndpointPathException.class,
        () -> PathNormalizer.normalize("/api/%2e%2e/../system"));
  }

  // ------------------------------------------------------------ 空段与结尾斜杠

  @ParameterizedTest
  @ValueSource(strings = {"/api//audits", "//api/audits", "/api/audits/", "/api/audits//"})
  void rejectsEmptySegmentsAndTrailingSlash(String path) {
    assertThrows(PathNormalizer.InvalidEndpointPathException.class, () -> PathNormalizer.normalize(path));
  }

  @Test
  void acceptsRootPathButRejectsDoubleSlashRoot() {
    // 根路径 "/" 会被切成单个空段，这是唯一合法的空段情形。
    assertEquals("/", PathNormalizer.normalize("/"));
    assertThrows(
        PathNormalizer.InvalidEndpointPathException.class, () -> PathNormalizer.normalize("//"));
  }

  @ParameterizedTest
  @ValueSource(strings = {"/api/./audits", "/./api/audits", "/api/."})
  void rejectsSingleDotSegments(String path) {
    assertThrows(PathNormalizer.InvalidEndpointPathException.class, () -> PathNormalizer.normalize(path));
  }

  // ------------------------------------------------------------ 大小写与编码绕过

  @Test
  void encodedBackslashAndSlashAreRejected() {
    assertThrows(
        PathNormalizer.InvalidEndpointPathException.class,
        () -> PathNormalizer.normalize("/api%5csystem%5cshutdown"));
    assertThrows(
        PathNormalizer.InvalidEndpointPathException.class,
        () -> PathNormalizer.normalize("/api%2fsystem%2fshutdown"));
    assertThrows(
        PathNormalizer.InvalidEndpointPathException.class, () -> PathNormalizer.normalize("/api\\system"));
  }

  @Test
  void encodedNullByteIsRejected() {
    assertThrows(
        PathNormalizer.InvalidEndpointPathException.class, () -> PathNormalizer.normalize("/api/audits%00"));
  }

  @Test
  void caseVariationsOfEncodedDotsAreRejected() {
    // %2E 与 %2e 等价，大写形式同样必须被拒——否则大小写绕过即可恢复路径遍历。
    for (String path :
        List.of(
            "/api/%2E%2E/system",
            "/api/%2e%2E/system",
            "/api/%2E%2e/system",
            "/api/%252E%252E/system")) {
      assertFalse(PathNormalizer.isValid(path), path + " 应被拒绝");
    }
  }

  @Test
  void incompletePercentEscapeIsRejected() {
    assertThrows(
        PathNormalizer.InvalidEndpointPathException.class, () -> PathNormalizer.normalize("/api/%2"));
    assertThrows(
        PathNormalizer.InvalidEndpointPathException.class, () -> PathNormalizer.normalize("/api/%zz"));
    assertThrows(
        PathNormalizer.InvalidEndpointPathException.class, () -> PathNormalizer.normalize("/api/%"));
  }

  @Test
  void nonAsciiAndFullWidthSlashAreRejected() {
    // 全角斜杠在某些下游组件里会被规范化成 /，属于 Unicode 规范化差异，必须拒绝。
    assertThrows(
        PathNormalizer.InvalidEndpointPathException.class, () -> PathNormalizer.normalize("/api／audits"));
    assertThrows(
        PathNormalizer.InvalidEndpointPathException.class, () -> PathNormalizer.normalize("/api/审计"));
  }

  // ------------------------------------------------------------ 结构性问题

  @Test
  void rejectsMissingLeadingSlash() {
    assertThrows(
        PathNormalizer.InvalidEndpointPathException.class, () -> PathNormalizer.normalize("api/audits"));
    assertThrows(
        PathNormalizer.InvalidEndpointPathException.class,
        () -> PathNormalizer.normalize("http://evil.example.com/api/audits"));
  }

  @Test
  void rejectsProtocolRelativeUrl() {
    // "//evil.example.com" 在浏览器语义下是协议相对 URL；空段校验已能拦住，这里显式固化该行为。
    assertThrows(
        PathNormalizer.InvalidEndpointPathException.class,
        () -> PathNormalizer.normalize("//evil.example.com/api"));
  }

  @Test
  void rejectsNullAndOversizedPaths() {
    assertThrows(PathNormalizer.InvalidEndpointPathException.class, () -> PathNormalizer.normalize(null));
    String oversized = "/api/" + "a".repeat(PathNormalizer.MAX_LENGTH);
    assertThrows(
        PathNormalizer.InvalidEndpointPathException.class, () -> PathNormalizer.normalize(oversized));
  }

  @Test
  void rejectsQueryStringAndFragment() {
    assertThrows(
        PathNormalizer.InvalidEndpointPathException.class,
        () -> PathNormalizer.normalize("/api/audits?page=1"));
    assertThrows(
        PathNormalizer.InvalidEndpointPathException.class,
        () -> PathNormalizer.normalize("/api/audits#top"));
  }

  @Test
  void rejectsControlCharactersAndWhitespace() {
    assertThrows(
        PathNormalizer.InvalidEndpointPathException.class, () -> PathNormalizer.normalize("/api/au\tdits"));
    assertThrows(
        PathNormalizer.InvalidEndpointPathException.class, () -> PathNormalizer.normalize("/api/au dits"));
    assertThrows(
        PathNormalizer.InvalidEndpointPathException.class, () -> PathNormalizer.normalize("/api/au\ndits"));
  }

  // ------------------------------------------------------------ 恒等性（核心不变量）

  @Test
  void normalizationNeverRewritesAPath() {
    // 本类的核心不变量：规范化结果与输入完全相等。
    // 若这条不变量被打破，"匹配注册表用的路径"就可能与实际请求的路径不同，那正是 §6.5 要防的解析差异。
    List<String> samples =
        List.of("/api/audits", "/api/targets/1/x", "/api/a%20b", "/api/a-b_c.d~e", "/api/targets/{id}");
    for (String sample : samples) {
      assertEquals(sample, PathNormalizer.normalize(sample), sample);
    }
  }

  // ------------------------------------------------------------ 前缀判定

  @ParameterizedTest
  @CsvSource({
    "/api/audits,/api,true",
    "/api/audits/1,/api,true",
    "/api,/api,true",
    // /api/audits-extra 确实是 /api 之下的一个路径段（"audits-extra" 是一段），因此为 true。
    // 这里真正要防的是"字符串前缀"误判：/apix 不是 /api 之下的路径。
    "/api/audits-extra,/api,true",
    "/apix,/api,false",
    "/other,/api,false",
    "/apiary,/api,false"
  })
  void prefixCheckComparesWholeSegments(String path, String prefix, boolean expected) {
    assertEquals(expected, PathNormalizer.isUnderPrefix(path, prefix));
  }

  @Test
  void prefixCheckRejectsStringPrefixFalsePositives() {
    // 这是本方法存在的理由：字符串前缀比较会把 /apix 误判为在 /api 之下。
    assertFalse("/apix".startsWith("/api/"));
    assertTrue("/apix".startsWith("/api"));
    assertFalse(PathNormalizer.isUnderPrefix("/apix", "/api"));
    assertFalse(PathNormalizer.isUnderPrefix("/apiary", "/api"));
  }

  @Test
  void prefixCheckToleratesTrailingSlashInPrefix() {
    assertTrue(PathNormalizer.isUnderPrefix("/api/audits", "/api/"));
    assertFalse(PathNormalizer.isUnderPrefix(null, "/api"));
    assertFalse(PathNormalizer.isUnderPrefix("/api/audits", null));
  }

  @Test
  void segmentsExposePathStructure() {
    assertEquals(List.of("api", "audits"), PathNormalizer.segments("/api/audits"));
    assertEquals(List.of("api", "targets", "{targetId}", "x"), PathNormalizer.segments("/api/targets/{targetId}/x"));
    assertEquals(List.of(""), PathNormalizer.segments("/"));
  }
}
