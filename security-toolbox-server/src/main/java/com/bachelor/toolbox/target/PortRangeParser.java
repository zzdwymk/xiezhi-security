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
      String token = rawToken.trim();
      if (token.isEmpty()) {
        throw invalidFormat();
      }

      int separator = token.indexOf('-');
      if (separator < 0) {
        add(ports, parsePort(token), maxPorts);
        continue;
      }
      if (separator != token.lastIndexOf('-')) {
        throw invalidFormat();
      }

      int start = parsePort(token.substring(0, separator).trim());
      int end = parsePort(token.substring(separator + 1).trim());
      if (start > end) {
        throw new ApiException("端口范围起始值不能大于结束值");
      }
      for (int port = start; port <= end; port++) {
        add(ports, port, maxPorts);
      }
    }

    return ports;
  }

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
