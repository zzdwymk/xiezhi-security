package com.bachelor.toolbox.target;

import com.bachelor.toolbox.common.ApiException;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import org.springframework.stereotype.Component;

/**
 * Parses a comma-separated TCP port specification such as {@code 80,443,8000-8010}. The result
 * preserves input order and removes duplicates.
 */
@Component
public class PortRangeParser {
  public static final int MIN_PORT = 1;
  public static final int MAX_PORT = 65535;

  public Set<Integer> parse(String specification) {
    return parse(specification, MAX_PORT);
  }

  public Set<Integer> parse(String specification, int maxPorts) {
    if (maxPorts < 1 || maxPorts > MAX_PORT) {
      throw new IllegalArgumentException("maxPorts 必须在 1-65535 范围内");
    }
    if (specification == null || specification.isBlank()) {
      throw invalidFormat();
    }

    LinkedHashSet<Integer> ports = new LinkedHashSet<>();
    String[] tokens = specification.split(",", -1);
    for (String rawToken : tokens) {
      PortRange range = parseRange(rawToken);
      for (int port = range.start(); port <= range.end(); port++) {
        add(ports, port, maxPorts);
      }
    }

    return ports;
  }

  /**
   * Tests membership without expanding ranges into a port collection.
   *
   * <p>Uses the same strict token validation as {@link #parse(String)} and validates every token,
   * even after a match. An invalid suffix must not turn a malformed authorization into a valid one.
   * A full {@code 1-65535} scope therefore needs only two endpoint parses, not 65,535 allocations.
   */
  public boolean containsPort(String specification, int requestedPort) {
    if (specification == null || specification.isBlank()) {
      throw invalidFormat();
    }
    boolean contains = false;
    for (String rawToken : specification.split(",", -1)) {
      PortRange range = parseRange(rawToken);
      contains |= requestedPort >= range.start() && requestedPort <= range.end();
    }
    return contains;
  }

  /**
   * 按输入顺序取前 {@code limit} 个端口，用于「只探测少量候选端口」的场景。
   *
   * <p>与 {@link #parse(String)} 使用同一严格 token 校验，但**不会**因为范围宽就展开全部端口：
   * {@code 1-65535} 取前 8 个不会产生 65,535 个 Integer 分配。命中限额后仍会继续校验剩余 token，
   * 避免非法后缀被"取够就停"掩盖。
   */
  public java.util.List<Integer> firstPorts(String specification, int limit) {
    if (limit < 1) {
      throw new IllegalArgumentException("limit 必须大于 0");
    }
    if (specification == null || specification.isBlank()) {
      throw invalidFormat();
    }
    java.util.List<Integer> selected = new java.util.ArrayList<>(Math.min(limit, 64));
    for (String rawToken : specification.split(",", -1)) {
      PortRange range = parseRange(rawToken);
      for (int port = range.start(); port <= range.end() && selected.size() < limit; port++) {
        selected.add(port);
      }
    }
    return selected;
  }

  private PortRange parseRange(String rawToken) {
    String token = rawToken.trim();
    if (token.isEmpty()) throw invalidFormat();
    int separator = token.indexOf('-');
    if (separator < 0) {
      int port = parsePort(token);
      return new PortRange(port, port);
    }
    if (separator != token.lastIndexOf('-')) throw invalidFormat();
    int start = parsePort(token.substring(0, separator).trim());
    int end = parsePort(token.substring(separator + 1).trim());
    if (start > end) throw new ApiException("端口范围起始值不能大于结束值");
    return new PortRange(start, end);
  }

  private record PortRange(int start, int end) {}

  public String canonicalize(String specification, int maxPorts) {
    return parse(specification, maxPorts).stream()
        .map(String::valueOf)
        .collect(Collectors.joining(","));
  }

  /**
   * Canonicalizes a port selection without expanding contiguous ranges. This is intended for
   * persisted authorization scopes and Nmap command parameters, where {@code 1-65535} must stay
   * compact.
   */
  public String canonicalizeCompact(String specification, int maxPorts) {
    List<Integer> ports = parse(specification, maxPorts).stream().sorted().toList();
    StringBuilder compact = new StringBuilder();
    int rangeStart = ports.get(0);
    int previous = rangeStart;
    for (int index = 1; index < ports.size(); index++) {
      int current = ports.get(index);
      if (current == previous + 1) {
        previous = current;
        continue;
      }
      appendRange(compact, rangeStart, previous);
      rangeStart = current;
      previous = current;
    }
    appendRange(compact, rangeStart, previous);
    return compact.toString();
  }

  private void appendRange(StringBuilder compact, int start, int end) {
    if (!compact.isEmpty()) compact.append(',');
    compact.append(start);
    if (end > start) compact.append('-').append(end);
  }

  private int parsePort(String value) {
    if (value.isEmpty() || !value.chars().allMatch(Character::isDigit)) {
      throw invalidFormat();
    }
    try {
      int port = Integer.parseInt(value);
      if (port < MIN_PORT || port > MAX_PORT) {
        throw new ApiException("端口必须在 1-65535 范围内");
      }
      return port;
    } catch (NumberFormatException ex) {
      throw new ApiException("端口必须在 1-65535 范围内");
    }
  }

  private void add(Set<Integer> ports, int port, int maxPorts) {
    ports.add(port);
    if (ports.size() > maxPorts) {
      throw new ApiException("单次最多允许 " + maxPorts + " 个端口");
    }
  }

  private ApiException invalidFormat() {
    return new ApiException("端口格式应为逗号分隔的端口或范围，例如 80,443,8000-8010");
  }
}
