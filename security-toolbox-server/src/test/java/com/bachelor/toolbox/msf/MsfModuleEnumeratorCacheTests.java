package com.bachelor.toolbox.msf;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.dependency.ExecutableLocator;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * 第310轮：MSF 模块枚举必须有短时缓存。
 *
 * <p>{@code GET /api/msf/modules} 每次请求都会 {@code Files.walk} 整个 MSF 模块目录（上限 20 万条）。
 * 未安装缓存时，任何登录用户都可以反复触发全盘扫描，造成明显的 CPU/IO 压力。本测试锁定"同一时间窗内
 * 第二次调用不再重新扫描"。
 */
class MsfModuleEnumeratorCacheTests {
  @TempDir Path temp;

  private MsfModuleEnumerator enumerator() throws Exception {
    Path install = temp.resolve("install");
    Path moduleDir = install.resolve("embedded").resolve("framework").resolve("modules").resolve("auxiliary");
    Files.createDirectories(moduleDir.resolve("test"));
    Path moduleFile = moduleDir.resolve("test").resolve("cached_probe.rb");
    Files.writeString(moduleFile, "class MetasploitModule; end\n");
    Path executable = install.resolve("msfconsole");
    Files.writeString(executable, "");

    ExecutableLocator locator = mock(ExecutableLocator.class);
    when(locator.find(anyList())).thenReturn(Optional.of(executable));
    return new MsfModuleEnumerator(locator, "msfconsole");
  }

  @Test
  void secondCallWithinTtlUsesCache() throws Exception {
    MsfModuleEnumerator enumerator = enumerator();
    List<MsfModuleOutputParser.MsfLine> first = enumerator.enumerate();
    assertThat(first).hasSize(1);

    // 删除模块文件：若未命中缓存，第二次枚举会得到空列表
    Path moduleFile =
        temp.resolve("install")
            .resolve("embedded")
            .resolve("framework")
            .resolve("modules")
            .resolve("auxiliary")
            .resolve("test")
            .resolve("cached_probe.rb");
    Files.delete(moduleFile);

    List<MsfModuleOutputParser.MsfLine> second = enumerator.enumerate();
    assertThat(second)
        .as("同一时间窗内的第二次枚举必须命中缓存，不能重新扫描文件系统")
        .hasSize(1);
  }
}

