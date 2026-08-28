package com.bachelor.toolbox.fingerprint;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HexFormat;

/**
 * Favicon 哈希算法工具类，提供与 EHole、FOFA、ObserverWard 一致的哈希计算：
 * 1. MurmurHash3_x86_32（计算以标准 76 字符换行格式 Base64 编码后的哈希）
 * 2. MD5 哈希
 */
public final class FaviconHashUtil {
  private FaviconHashUtil() {}

  /**
   * 计算与 FOFA / EHole 标准一致的 Favicon MurmurHash3 (32-bit signed int 字符串)。
   * 标准规范：
   * 1. 原始图标字节进行标准 Base64 编码，每 76 个字符插入一个换行符 '\n'，末尾补一个 '\n'（即 RFC 2045 MIME 换行格式）。
   * 2. 对该换行 Base64 字符串的 UTF-8 字节计算 MurmurHash3_x86_32。
   */
  public static String calculateMurmur3(byte[] faviconBytes) {
    if (faviconBytes == null || faviconBytes.length == 0) {
      return "";
    }
    String mimeBase64 = toMimeBase64WithTrailingNewline(faviconBytes);
    byte[] base64Bytes = mimeBase64.getBytes(StandardCharsets.UTF_8);
    int hash = murmur3_32(base64Bytes, 0, base64Bytes.length, 0);
    return String.valueOf(hash);
  }

  /**
   * 计算图标的 MD5 散列（小写 32 位）。
   */
  public static String calculateMd5(byte[] faviconBytes) {
    if (faviconBytes == null || faviconBytes.length == 0) {
      return "";
    }
    try {
      MessageDigest md = MessageDigest.getInstance("MD5");
      byte[] digest = md.digest(faviconBytes);
      return HexFormat.of().formatHex(digest);
    } catch (NoSuchAlgorithmException ex) {
      return "";
    }
  }

  /**
   * 按 RFC 2045 MIME 标准 Base64 编码并在末尾附加换行符 '\n'。
   */
  private static String toMimeBase64WithTrailingNewline(byte[] data) {
    String mimeEncoded = Base64.getMimeEncoder(76, new byte[] {'\n'}).encodeToString(data);
    return mimeEncoded + "\n";
  }

  /**
   * MurmurHash3_x86_32 核心算法实现。
   */
  public static int murmur3_32(byte[] data, int offset, int len, int seed) {
    int h1 = seed;
    int c1 = 0xcc9e2d51;
    int c2 = 0x1b873593;

    int nblocks = len / 4;

    for (int i = 0; i < nblocks; i++) {
      int index = offset + (i * 4);
      int k1 = (data[index] & 0xff)
          | ((data[index + 1] & 0xff) << 8)
          | ((data[index + 2] & 0xff) << 16)
          | ((data[index + 3] & 0xff) << 24);

      k1 *= c1;
      k1 = (k1 << 15) | (k1 >>> 17);
      k1 *= c2;

      h1 ^= k1;
      h1 = (h1 << 13) | (h1 >>> 19);
      h1 = h1 * 5 + 0xe6546b64;
    }

    int tailIndex = offset + (nblocks * 4);
    int k1 = 0;

    switch (len & 3) {
      case 3:
        k1 ^= (data[tailIndex + 2] & 0xff) << 16;
        // fall through
      case 2:
        k1 ^= (data[tailIndex + 1] & 0xff) << 8;
        // fall through
      case 1:
        k1 ^= (data[tailIndex] & 0xff);
        k1 *= c1;
        k1 = (k1 << 15) | (k1 >>> 17);
        k1 *= c2;
        h1 ^= k1;
        break;
      default:
        break;
    }

    h1 ^= len;

    h1 ^= h1 >>> 16;
    h1 *= 0x85ebca6b;
    h1 ^= h1 >>> 13;
    h1 *= 0xc2b2ae35;
    h1 ^= h1 >>> 16;

    return h1;
  }
}
