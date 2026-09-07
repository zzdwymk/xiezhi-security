package com.bachelor.toolbox.dependency;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;

public record SystemDependenciesResponse(
    String os, String arch, String database, List<DependencyStatus> dependencies) {
  /**
   * 依赖项指纹。由 name+status+version 生成，用于主动检测启动前“比对哈希”判定该项依赖（扫描器）
   * 是否存在，避免每次强刷重跑版本检测。不包含 path，避免向未认证方泄露安装路径，且对鉴权与否保持稳定。
   */
  public record DependencyStatus(
      String name,
      String status,
      String version,
      String path,
      boolean required,
      String category,
      String message,
      String hash,
      String dirHash) {

    public static String hashOf(String name, String status, String version) {
      String source = String.join("|", name, status, version == null ? "" : version);
      try {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return HexFormat.of().formatHex(digest.digest(source.getBytes(StandardCharsets.UTF_8)));
      } catch (Exception ex) {
        return null;
      }
    }
  }
}
