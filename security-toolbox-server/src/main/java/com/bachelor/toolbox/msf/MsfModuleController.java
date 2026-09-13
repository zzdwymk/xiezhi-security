package com.bachelor.toolbox.msf;

import com.bachelor.toolbox.common.ApiException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * 供工作流 MSF 节点配置读取本机已安装 MetasploitFramework 的模块分类清单。
 *
 * <p>直接复用 {@link MsfModuleEnumerator} 的文件系统枚举（比启动 msfconsole 控制台更快、更稳），
 * 仅返回 {@code auxiliary}/exploit 两类的模块路径、名称与等级，前端据此做分类下拉（多选、全选、
 * 分类全选）。MSF 未安装或枚举失败时返回 available=false，前端降级为手动输入模块。
 *
 * <p>{@code /modules/options} 用于按需读取单个模块的 Datastore 选项，辅助前端回填「必要配置」。
 */
@RestController
@RequestMapping("/api/msf")
public class MsfModuleController {
  private static final Logger log = LoggerFactory.getLogger(MsfModuleController.class);

  private final MsfModuleEnumerator enumerator;
  private final MsfModuleOptionService optionService;

  public MsfModuleController(
      MsfModuleEnumerator enumerator, MsfModuleOptionService optionService) {
    this.enumerator = enumerator;
    this.optionService = optionService;
  }

  @GetMapping("/modules")
  public MsfModuleCatalog modules() {
    boolean available;
    List<MsfModuleOutputParser.MsfLine> lines;
    try {
      lines = enumerator.enumerate();
      available = true;
    } catch (ApiException ex) {
      available = false;
      lines = List.of();
    } catch (RuntimeException ex) {
      log.warn("MSF 模块枚举失败，前端降级为手动模块", ex);
      available = false;
      lines = List.of();
    }

    MsfModuleCatalog catalog = new MsfModuleCatalog(available, new ArrayList<>());
    for (String code : List.of("auxiliary", "exploit")) {
      List<Item> items = new ArrayList<>();
      for (MsfModuleOutputParser.MsfLine line : lines) {
        if (line.category() == null
            || !line.category().equalsIgnoreCase(code)
            || line.modulePath() == null
            || line.modulePath().isBlank()) {
          continue;
        }
        items.add(
            new Item(
                line.modulePath(),
                line.name() == null ? "" : line.name(),
                line.rank() == null ? "normal" : line.rank(),
                line.description() == null ? "" : line.description()));
      }
      catalog.categories().add(new Category(code, label(code), List.copyOf(items)));
    }
    return catalog;
  }

  private String label(String code) {
    if ("exploit".equalsIgnoreCase(code)) return "exploit（利用模块）";
    return "auxiliary（辅助探测）";
  }

  /** 按需读取单个模块的 Datastore 选项，供前端自动回填必要配置。 */
  @GetMapping("/modules/options")
  public MsfModuleOptions options(@RequestParam("module") String module) {
    return new MsfModuleOptions(optionService.options(module));
  }

  /** 单个模块，modulePath 即 MSF 模块全路径（如 auxiliary/scanner/ssh/ssh_login）。 */
  public record Item(String modulePath, String name, String rank, String description) {}

  public record Category(String category, String label, List<Item> modules) {}

  public record MsfModuleCatalog(boolean available, List<Category> categories) {}

  public record MsfModuleOptions(List<MsfModuleOptionService.ModuleOption> options) {}
}