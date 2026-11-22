package com.bachelor.toolbox.msf;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import com.bachelor.toolbox.dependency.ExecutableLocator;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * 第311轮：MSF 模块选项必须缓存，避免每次请求都启动 msfconsole。
 *
 * <p>{@code GET /api/msf/modules/options} 的慢路径会启动 {@code msfconsole}（超时上限 600 秒）。
 * 未缓存时任何登录用户都可以反复请求，触发大量重量级进程。本测试锁定"同一模块短时间内只真正读取一次"。
 */
class MsfModuleOptionCacheTests {

  private static final class CountingService extends MsfModuleOptionService {
    private int loads;

    CountingService() {
      super(mock(ExecutableLocator.class), new ObjectMapper(), "msfconsole", 5);
    }

    @Override
    List<ModuleOption> loadOptions(String module) {
      loads++;
      return List.of(new ModuleOption("TARGETURI", "string", false, "/", "目标路径"));
    }
  }

  @Test
  void repeatedRequestsForSameModuleOnlySpawnOnce() {
    CountingService service = new CountingService();

    List<MsfModuleOptionService.ModuleOption> first = service.options("auxiliary/scanner/http/title");
    List<MsfModuleOptionService.ModuleOption> second = service.options("auxiliary/scanner/http/title");

    assertThat(first).hasSize(1);
    assertThat(second).hasSize(1);
    assertThat(service.loads)
        .as("同一模块的重复请求必须命中缓存，不能每次都启动 msfconsole")
        .isEqualTo(1);
  }

  @Test
  void differentModulesAreCachedIndependently() {
    CountingService service = new CountingService();
    service.options("auxiliary/scanner/http/title");
    service.options("auxiliary/scanner/ftp/ftp_login");
    service.options("auxiliary/scanner/http/title");

    assertThat(service.loads).isEqualTo(2);
  }
}
