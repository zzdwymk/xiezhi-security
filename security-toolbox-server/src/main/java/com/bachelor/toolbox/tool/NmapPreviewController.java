package com.bachelor.toolbox.tool;

import com.bachelor.toolbox.common.ApiException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * 审批弹窗“本轮将执行命令”的只读预览接口。
 *
 * <p>预览必须与真正下发的命令同源，否则管理员批准的是 A、系统执行的是 B。前端曾各自拼装命令，
 * 结果漏掉了 {@code -Pn -T4}、把 {@code -sV -O --version-light} 拆成会被 Nmap 当成输出文件名的
 * 裸参数。这里统一由 {@link NmapServiceScanTool} 构建，前端只负责展示。
 *
 * <p>接口不触碰任何目标：不读取授权登记、不解析主机、不探测网络，只根据模式与端口拼出 argv。
 */
@RestController
@RequestMapping("/api/tools")
public class NmapPreviewController {
  private static final int MAX_HOST_LENGTH = 255;
  private static final int MAX_PORTS_LENGTH = 200;

  private final NmapServiceScanTool nmap;

  public NmapPreviewController(NmapServiceScanTool nmap) {
    this.nmap = nmap;
  }

  @GetMapping("/nmap/preview")
  public Map<String, Object> preview(
      @RequestParam String mode,
      @RequestParam(required = false, defaultValue = "1-65535") String ports,
      @RequestParam(required = false) String host) {
    String normalizedHost = host == null ? "" : host.trim();
    if (normalizedHost.length() > MAX_HOST_LENGTH) {
      throw new ApiException("Nmap 预览目标过长");
    }
    String normalizedPorts = ports == null ? "" : ports.trim();
    if (normalizedPorts.isEmpty() || normalizedPorts.length() > MAX_PORTS_LENGTH) {
      throw new ApiException("Nmap 预览端口不能为空或过长");
    }
    List<String> command =
        withTarget(nmap.commandPreview(normalizedHost, normalizedPorts, mode), normalizedHost);
    Map<String, Object> response = new LinkedHashMap<>();
    response.put("tool", nmap.code());
    // 空主机时尾部给占位符，保证命令形态（参数顺序）与真实下发一致。
    response.put("command", String.join(" ", command));
    response.put("arguments", command);
    response.put(
        "targetConvergesToProbeResult",
        command.contains(NmapServiceScanTool.CONSUMED_PORTS_PLACEHOLDER));
    return response;
  }

  private List<String> withTarget(List<String> command, String host) {
    if (!host.isEmpty()) return command;
    List<String> copy = new ArrayList<>(command);
    copy.set(copy.size() - 1, "<目标>");
    return List.copyOf(copy);
  }
}
