package com.bachelor.toolbox.tool;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.bachelor.toolbox.dependency.NmapExecutableResolver;
import com.bachelor.toolbox.target.PortRangeParser;
import com.bachelor.toolbox.target.TargetPolicyService;
import java.util.Optional;
import org.junit.jupiter.api.Test;

/** 审批弹窗的命令预览接口：只拼 argv，不解析目标、不探测网络。 */
class NmapPreviewControllerTests {

  @Test
  void previewsTheSameArgvThatWillBeDispatched() {
    var controller = controller();

    var preview = controller.preview("quick", "1-65535", "192.168.222.149");

    assertThat(preview.get("arguments").toString())
        .isEqualTo("[nmap, -sT, -n, -Pn, -T4, " + NmapServiceScanTool.CONSUMED_PORTS_PLACEHOLDER
            + ", --stats-every, 1s, -oX, -, 192.168.222.149]");
    assertThat(preview.get("targetConvergesToProbeResult")).isEqualTo(true);
  }

  @Test
  void keepsServiceIdentificationFlagsAsOneArgument() {
    var controller = controller();

    var preview = controller.preview("service", "80,443", "192.168.222.149");

    assertThat((String) preview.get("command"))
        .isEqualTo(
            "nmap -sT -n -sV -T4 -O --version-light -p 80,443 --stats-every 1s -oX - 192.168.222.149");
  }

  @Test
  void fallsBackToPlaceholderOnlyWhenNoHostIsGiven() {
    var controller = controller();

    String withoutHost = (String) controller.preview("quick", "80", null).get("command");
    String withHost = (String) controller.preview("quick", "80", "192.0.2.1").get("command");

    assertThat(withoutHost).endsWith("-oX - <目标>");
    assertThat(withHost).endsWith("-oX - 192.0.2.1");
    assertThat(withoutHost).isEqualTo(withHost.replace("192.0.2.1", "<目标>"));
  }

  @Test
  void rejectsUnknownModesInsteadOfPreviewingSomethingElse() {
    var controller = controller();

    assertThatThrownBy(() -> controller.preview("made-up", "80", "192.0.2.1"))
        .hasMessageContaining("Nmap 扫描模式无效");
  }

  private NmapPreviewController controller() {
    NmapServiceScanTool tool =
        new NmapServiceScanTool(
            new TargetPolicyService(false, new PortRangeParser()),
            new PortRangeParser(),
            new NmapExecutableResolver(candidates -> Optional.empty(), "nmap"),
            65535,
            60,
            600);
    return new NmapPreviewController(tool);
  }
}
