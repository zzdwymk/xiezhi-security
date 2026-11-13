package com.bachelor.toolbox.common;

import java.io.IOException;
import java.io.Reader;

/**
 * 有界行读取器（Round 17）。
 *
 * <p>标准 {@link java.io.BufferedReader#readLine()} 对单行长度没有任何上限：若上游（AI 运行时 / 模型网关 /
 * 被劫持的连接）持续发送不含换行的超长字节流，{@code readLine()} 会一直读入内存直到 OOM。
 * 本类在逐字符读取时累计长度，超过 {@code maxLineLength} 立即抛 {@link IOException}，
 * 把"单行无限增长"的内存耗尽面收敛为可预期的异常。
 *
 * <p>语义与 {@code readLine()} 一致：返回不含行尾符的行内容；遇 EOF 且无数据返回 {@code null}。
 * 仅支持 {@code \n} 与 {@code \r\n} 两种行尾（与 HTTP/SSE 场景一致）。
 */
public final class BoundedLineReader {
  private final Reader reader;
  private final int maxLineLength;

  public BoundedLineReader(Reader reader, int maxLineLength) {
    this.reader = reader;
    this.maxLineLength = maxLineLength;
  }

  /** 读取一行；超长则抛 IOException。EOF 且无任何字符时返回 null。 */
  public String readLine() throws IOException {
    StringBuilder sb = new StringBuilder();
    int c;
    boolean any = false;
    while ((c = reader.read()) != -1) {
      any = true;
      if (c == '\n') {
        int len = sb.length();
        // 去掉行尾的 \r（\r\n 归一）
        if (len > 0 && sb.charAt(len - 1) == '\r') {
          sb.setLength(len - 1);
        }
        return sb.toString();
      }
      if (c == '\r') {
        // 暂存 \r，若是 \r\n 会在读入 \n 时去掉；若单独 \r 出现在行中，按普通字符保留以不改变内容。
        // 为了与 BufferedReader 行为近似，这里把 \r 当行内容的一部分处理（纯 \r 分隔的行较少见）。
      }
      sb.append((char) c);
      if (sb.length() > maxLineLength) {
        throw new IOException("单行内容超过上限 " + maxLineLength + " 字符");
      }
    }
    if (!any) {
      return null;
    }
    // EOF 收尾：去掉尾部 \r
    int len = sb.length();
    if (len > 0 && sb.charAt(len - 1) == '\r') {
      sb.setLength(len - 1);
    }
    return sb.toString();
  }
}
