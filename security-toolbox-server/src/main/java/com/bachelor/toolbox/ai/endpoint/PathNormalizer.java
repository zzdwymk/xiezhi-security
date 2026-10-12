package com.bachelor.toolbox.ai.endpoint;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * 端点路径规范化（设计文档 §6.5 第三重约束）。
 *
 * <p>{@code invoke_endpoint} 接受模型给出的任意路径字符串。若不规范化就直接拿去匹配端点注册表，会出现两类绕过：
 *
 * <ol>
 *   <li><b>注册表匹配绕过</b>：{@code /api/audits/../system/shutdown} 在 HTTP 层会被解析为 {@code /api/system/shutdown}
 *       ，但字符串比较时与注册表里的 {@code /api/system/shutdown} 不相等——于是"未知端点"检查被绕过，而真实请求打到了黑名单端点。
 *   <li><b>黑名单绕过</b>：即使注册表匹配成功，规范化后可能与匹配时使用的路径不是同一个资源。
 * </ol>
 *
 * <p>因此本类采取 <b>fail-closed 的"规范化前后必须完全相等"策略</b>：任何需要改写才能变成合法形式的路径一律拒绝，而不是"改写后放行"。这样
 * "匹配用的路径"与"实际请求的路径"恒等，不存在解析差异。
 *
 * <h2>拒绝的输入</h2>
 *
 * <ul>
 *   <li>含 {@code ..} 路径段的遍历（含 URL 编码 {@code %2e%2e}、{@code %2E%2E}、双重编码 {@code %252e}）
 *   <li>空段（{@code //}）、{@code .} 段、结尾斜杠（{@code /api/audits/}）
 *   <li>反斜杠（{@code \}）、{@code %5c}、{@code %00}、{@code %2f} 等可能改变服务器路由语义的编码
 *   <li>绝对 URL（{@code http://...}）、协议相对 URL（{@code //evil}）、含 {@code ?} 或 {@code #} 的路径
 *   <li>控制字符、空白、非 ASCII 字符（避免 Unicode 规范化差异，如全角斜杠 {@code ／}）
 * </ul>
 *
 * <h2>允许但不改写的形式</h2>
 *
 * <p>模板占位符段 {@code {id}}、{@code {targetId}} 原样保留，仅校验其字符集。
 */
public final class PathNormalizer {

  /**
   * 允许出现在字面段中的字符。
   *
   * <p>包含 {@code %}，因为段内允许百分号编码（如 {@code %20}）；转义本身是否合法、是否危险由
   * {@link #rejectEncodedDanger} 单独判定——把编码校验塞进字符集正则会让"哪些编码被拒"变得不可读。
   */
  private static final Pattern SAFE_SEGMENT = Pattern.compile("[A-Za-z0-9._~!$&'()*+,;=:@%\\-]+");

  /** 允许出现在模板占位符段中的字符。 */
  private static final Pattern TEMPLATE_SEGMENT = Pattern.compile("\\{[A-Za-z0-9_]+(:[^}]*)?}");

  /** 最大路径长度，防止用超长路径拖垮扫描或日志。 */
  public static final int MAX_LENGTH = 2048;

  private PathNormalizer() {}

  /**
   * 规范化并校验路径。
   *
   * @param path 原始路径，允许为 {@code null}
   * @return 规范化后的路径（对合法输入，其值与原输入去掉首尾空白后完全相等）
   * @throws InvalidEndpointPathException 路径不合法或需要改写才能合法时抛出
   */
  public static String normalize(String path) {
    if (path == null) {
      throw new InvalidEndpointPathException("端点路径不能为空");
    }
    String candidate = path;
    if (candidate.length() > MAX_LENGTH) {
      throw new InvalidEndpointPathException("端点路径过长，超过 " + MAX_LENGTH + " 字符");
    }
    if (!candidate.startsWith("/")) {
      throw new InvalidEndpointPathException("端点路径必须以 / 开头: " + candidate);
    }
    rejectSuspiciousCharacters(candidate);
    rejectEncodedDanger(candidate);

    List<String> segments = splitSegments(candidate);
    for (String segment : segments) {
      if (segment.equals("..")) {
        throw new InvalidEndpointPathException("端点路径不允许包含上级目录引用: " + candidate);
      }
      if (segment.equals(".")) {
        throw new InvalidEndpointPathException("端点路径不允许包含当前目录引用: " + candidate);
      }
      if (segment.isEmpty()) {
        // 根路径 "/" 会被切成单个空段，这是合法路径；其余位置的空段（"//"、结尾斜杠）一律拒绝。
        if (candidate.equals("/")) {
          continue;
        }
        throw new InvalidEndpointPathException("端点路径不允许包含空路径段（// 或结尾斜杠）: " + candidate);
      }
      if (!TEMPLATE_SEGMENT.matcher(segment).matches()
          && !SAFE_SEGMENT.matcher(segment).matches()) {
        throw new InvalidEndpointPathException("端点路径包含非法字符的路径段: " + segment);
      }
    }
    // 本类刻意不做任何"改写"：合法的规范化结果就是原字符串本身。
    // 若这里返回了与输入不同的值，就说明存在"匹配用的路径"与"实际请求的路径"不一致的可能，
    // 那正是 §6.5 要防的解析差异。调用方（InvokeEndpointCapability）会再断言一次相等。
    return candidate;
  }

  /**
   * 判断路径是否合法（不抛异常的便捷形式）。
   *
   * @param path 待判定路径
   * @return 合法返回 {@code true}
   */
  public static boolean isValid(String path) {
    try {
      normalize(path);
      return true;
    } catch (InvalidEndpointPathException error) {
      return false;
    }
  }

  /**
   * 判断规范化后的路径是否仍在给定前缀下（供未来按域收敛权限使用）。
   *
   * <p>比较按 <b>路径段</b> 而非字符串前缀进行。这一点必须做对：{@code "/api/audits-extra".startsWith("/api/")} 为
   * {@code true}，若用字符串前缀判断，{@code /api/audits-extra} 就会被误判为在 {@code /api} 之下，未来按域收敛权限时
   * 会放行不属于该域的端点。因此这里逐段比较。
   *
   * <p>前缀允许带结尾斜杠（{@code /api/} 与 {@code /api} 等价），也允许 {@code null} 之外的任意合法路径；
   * 结尾斜杠产生的空段在比较前被剔除。
   */
  public static boolean isUnderPrefix(String normalizedPath, String prefix) {
    if (normalizedPath == null || prefix == null) return false;
    if (normalizedPath.equals(prefix)) return true;
    List<String> pathSegments = meaningfulSegments(normalizedPath);
    List<String> prefixSegments = meaningfulSegments(prefix);
    if (prefixSegments.isEmpty()) {
      // 空前缀（"/"）之下包含全部路径。
      return true;
    }
    if (pathSegments.size() <= prefixSegments.size()) {
      return false;
    }
    for (int index = 0; index < prefixSegments.size(); index++) {
      if (!pathSegments.get(index).equals(prefixSegments.get(index))) {
        return false;
      }
    }
    return true;
  }

  /** 分段并剔除结尾斜杠产生的空段，用于前缀比较。 */
  private static List<String> meaningfulSegments(String path) {
    List<String> segments = splitSegments(path);
    List<String> result = new ArrayList<>(segments.size());
    for (String segment : segments) {
      if (!segment.isEmpty()) {
        result.add(segment);
      }
    }
    return result;
  }

  /** 提取路径段（不含前导空段），供测试与调试使用。 */
  static List<String> segments(String path) {
    return splitSegments(path);
  }

  // ---------------------------------------------------------------- 内部实现

  private static List<String> splitSegments(String path) {
    List<String> segments = new ArrayList<>();
    int start = 1;
    for (int index = 1; index <= path.length(); index++) {
      if (index == path.length() || path.charAt(index) == '/') {
        segments.add(path.substring(start, index));
        start = index + 1;
      }
    }
    return segments;
  }

  /** 拒绝控制字符、空白、反斜杠、非 ASCII 与 URL 保留歧义字符。 */
  private static void rejectSuspiciousCharacters(String path) {
    for (int index = 0; index < path.length(); index++) {
      char current = path.charAt(index);
      if (current < 0x21 || current > 0x7e) {
        throw new InvalidEndpointPathException(
            "端点路径不允许包含控制字符、空白或非 ASCII 字符（位置 " + index + "）");
      }
      switch (current) {
        case '\\' -> throw new InvalidEndpointPathException("端点路径不允许包含反斜杠");
        case '?' -> throw new InvalidEndpointPathException("端点路径不允许包含查询串，请使用 query 参数");
        case '#' -> throw new InvalidEndpointPathException("端点路径不允许包含 URL 片段标识符 #");
        case '%' -> {
          // 百分号本身合法，但必须构成完整转义；具体危险编码在 rejectEncodedDanger 中判定。
        }
        default -> {
          // 其余可见 ASCII 字符交由分段字符集校验。
        }
      }
    }
  }

  /**
   * 先整体解码（仅用于<strong>检测</strong>，绝不用于改写），再判定是否含有危险序列。
   *
   * <p>这样能同时覆盖单重编码（{@code %2e%2e}）与双重编码（{@code %252e%252e}）：双重编码解码一次后仍是
   * {@code %2e%2e}，继续解码即得到 {@code ..}。
   *
   * <p>判定原则是"解码后不得出现<strong>结构</strong>变化"，而不是"不得出现任何特殊字符"：{@code %20} 解出空格、{@code
   * %2B} 解出 {@code +}，都不改变路径段的数量与归属，因此允许；而 {@code %2f}（解出 {@code /}）、{@code %5c}（解出
   * {@code \}）、{@code %00}、{@code %2e}（参与构成 {@code ..}）会改变路由解析结果，必须拒绝。
   */
  private static void rejectEncodedDanger(String path) {
    if (!path.contains("%")) {
      return;
    }
    if (!hasCompleteEscapes(path)) {
      throw new InvalidEndpointPathException("端点路径包含不完整的百分号转义: " + path);
    }
    String decoded = path;
    // 最多解码 3 层，足以覆盖双重/三重编码；再深也没有现实意义。
    for (int round = 0; round < 3; round++) {
      String next = safeDecode(decoded);
      if (next.equals(decoded)) {
        break;
      }
      decoded = next;
      checkDecoded(decoded, path);
    }
    checkDecoded(decoded, path);
  }

  /**
   * 判定解码结果是否引入了结构性危险。
   *
   * <p>关键点：解码结果里的 {@code /} <strong>并不都</strong>是危险的——原始路径本身就以 {@code /} 分段，前导斜杠与段间分隔符
   * 在解码结果里必然存在。危险的是"<strong>某个编码序列解出了 {@code /}</strong>"，因为它会把一个段拆成两个段，
   * 从而改变路由解析结果（{@code %2f} 是最典型的解析差异来源）。
   *
   * <p>因此本方法不检查"解码结果里有没有斜杠"，而是<strong>逐段</strong>检查：把原始路径与解码结果都按 {@code /} 分段，
   * 若两者段数不同，说明有编码序列引入了新的分隔符，立即拒绝；段数相同时再检查每个段内是否含危险字符。
   */
  private static void checkDecoded(String decoded, String original) {
    if (decoded.contains("..")) {
      throw new InvalidEndpointPathException("端点路径包含编码后的上级目录引用（路径遍历）: " + original);
    }
    if (decoded.indexOf('\\') >= 0) {
      throw new InvalidEndpointPathException("端点路径包含编码后的反斜杠: " + original);
    }
    if (decoded.indexOf('\0') >= 0) {
      throw new InvalidEndpointPathException("端点路径包含编码后的空字节: " + original);
    }

    List<String> originalSegments = splitSegments(original);
    List<String> decodedSegments = splitSegments(decoded);
    if (originalSegments.size() != decodedSegments.size()) {
      throw new InvalidEndpointPathException(
          "端点路径包含编码后的斜杠（会改变路径段结构）: " + original);
    }
    for (int index = 0; index < decodedSegments.size(); index++) {
      String decodedSegment = decodedSegments.get(index);
      String originalSegment = originalSegments.get(index);
      // 段内出现斜杠只可能来自编码，段数相等时理论上不会发生；保留判定作为第二道防线。
      if (decodedSegment.indexOf('/') >= 0) {
        throw new InvalidEndpointPathException("端点路径段内包含编码后的斜杠: " + original);
      }
      // 解码后变成 "." 或 ".." 的段属于目录引用，必须拒绝（原始文本里可能写作 %2e）。
      if (decodedSegment.equals(".") || decodedSegment.equals("..")) {
        throw new InvalidEndpointPathException("端点路径包含编码后的目录引用: " + original);
      }
      if (decodedSegment.isEmpty() && !originalSegment.isEmpty()) {
        throw new InvalidEndpointPathException("端点路径包含编码后消失的路径段: " + original);
      }
      for (int offset = 0; offset < decodedSegment.length(); offset++) {
        char current = decodedSegment.charAt(offset);
        if (current == '\t' || current == '\n' || current == '\r') {
          throw new InvalidEndpointPathException("端点路径包含编码后的控制字符: " + original);
        }
      }
    }
  }

  /** 校验每个 {@code %} 都紧跟两位十六进制数字。 */
  private static boolean hasCompleteEscapes(String path) {
    for (int index = 0; index < path.length(); index++) {
      if (path.charAt(index) != '%') {
        continue;
      }
      if (index + 2 >= path.length()
          || Character.digit(path.charAt(index + 1), 16) < 0
          || Character.digit(path.charAt(index + 2), 16) < 0) {
        return false;
      }
      index += 2;
    }
    return true;
  }

  /**
   * 解码百分号转义。
   *
   * <p>刻意不用 {@link URLDecoder#decode(String, java.nio.charset.Charset)}：它会把 {@code +} 解成空格，导致
   * {@code /a+b} 被误判。这里只处理 {@code %XX}。
   */
  private static String safeDecode(String value) {
    StringBuilder builder = new StringBuilder(value.length());
    for (int index = 0; index < value.length(); index++) {
      char current = value.charAt(index);
      if (current != '%' || index + 2 >= value.length()) {
        builder.append(current);
        continue;
      }
      int high = Character.digit(value.charAt(index + 1), 16);
      int low = Character.digit(value.charAt(index + 2), 16);
      if (high < 0 || low < 0) {
        builder.append(current);
        continue;
      }
      builder.append((char) (high * 16 + low));
      index += 2;
    }
    return builder.toString();
  }

  /** 路径校验失败异常。刻意独立于 {@code ApiException}，便于本类在无 Web 依赖处复用。 */
  public static final class InvalidEndpointPathException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    public InvalidEndpointPathException(String message) {
      super(Objects.requireNonNull(message));
    }
  }

  /** 仅供调试：返回按标准库解码的结果，不用于任何安全判定。 */
  static String decodeForDiagnostics(String value) {
    return URLDecoder.decode(value, StandardCharsets.UTF_8);
  }
}
