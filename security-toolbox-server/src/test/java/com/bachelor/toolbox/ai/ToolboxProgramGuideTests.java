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

  @Test
  void explainsFscanFlagsWithoutChangingHistoricalExecutionClaims() {
    assertThat(ToolboxProgramGuide.context())
        .contains("-np 禁用 ping 探测，不是禁用端口扫描", "-nopoc 禁用 PoC 扫描", "-nobr 禁用暴力破解")
        .contains("是否获得服务/版本信息必须根据实际输出判断")
        .contains("不能把当前默认配置当作该历史任务的已执行参数");
  }

  @Test
  void distinguishesAutomaticPlanApplicationsFromManualSecurityActionRecords() {
    assertThat(ToolboxProgramGuide.context())
        .contains("可自动提交 AI_PLAN_EXECUTION 申请", "管理员在界面批准后可恢复该原计划", "驳回不创建检测任务")
        .contains("申请高风险行动", "尚未接入 AI 提交", "只登记状态与人工证据")
        .contains("不是已注册的自动执行模板");
  }
}
