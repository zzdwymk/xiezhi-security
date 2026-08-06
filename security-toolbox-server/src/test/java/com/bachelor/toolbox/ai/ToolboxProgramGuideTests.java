package com.bachelor.toolbox.ai;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class ToolboxProgramGuideTests {
  @Test
  void describesRealPagesToolsAndExecutionBoundaries() {
    String guide = ToolboxProgramGuide.context();

    assertThat(guide)
        .contains("AI 安全助手")
        .contains("红队工作流")
        .contains("评估项目详情")
        .contains("漏洞库与主动检测")
        .contains("审计日志")
        .contains("nmap_service_scan")
        .contains("nuclei_scan")
        .contains("只有管理员明确确认后")
        .contains("不能提交任意命令、PoC 地址或自定义工具参数")
        .endsWith("\n");
  }
}
