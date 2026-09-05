package com.bachelor.toolbox.msf;

import java.time.Instant;

/**
 * 一条 Metasploit 模块的元数据。
 *
 * <p>MSF 模块来源于本机已安装的 Framework（非可分发的独立 poc 数据目录），因此没有模板文件
 * hash 语义（{@code templateSha256} 为空）。{@code modulePath} 即模块在框架内的完整路径，
 * 例如 {@code auxiliary/scanner/ssh/ssh_login}。只有 auxiliary 与 exploit 两个类别会被收录，
 * 与 {@code MsfScanTool} 的可执行白名单保持一致。
 */
public record MsfModuleMetadata(
    String modulePath,
    String name,
    String category,
    String rank,
    String severity,
    String description,
    byte[] content,
    Instant updatedAt) {}