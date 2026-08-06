package com.bachelor.toolbox.report;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.finding.Finding;
import com.bachelor.toolbox.finding.FindingRepository;
import com.bachelor.toolbox.target.AuthorizedTarget;
import com.bachelor.toolbox.target.TargetService;
import com.bachelor.toolbox.task.SecurityTask;
import com.bachelor.toolbox.task.SecurityTaskRepository;
import com.lowagie.text.Document;
import com.lowagie.text.DocumentException;
import com.lowagie.text.pdf.PdfWriter;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

class ProjectReportServiceTests {
  private TargetService targetService;
  private SecurityTaskRepository taskRepository;
  private FindingRepository findingRepository;
  private ProjectReportService service;

  @BeforeEach
  void setUp() {
    targetService = mock(TargetService.class);
    taskRepository = mock(SecurityTaskRepository.class);
    findingRepository = mock(FindingRepository.class);
    service = new ProjectReportService(targetService, taskRepository, findingRepository);
  }

  @Test
  void generatesEscapedProjectHtmlWithTaskSnapshotsAndSeveritySummary() {
    prepareData();

    String html = service.generateHtml(7L);

    assertThat(html)
        .contains("项目级授权安全测试报告", "CRITICAL", "Nuclei: template-hash", "漏洞&lt;script&gt;")
        .doesNotContain("漏洞<script>");
  }

  @Test
  void generatesAValidPdfDocument() {
    prepareData();

    byte[] pdf = service.generatePdf(7L);

    assertThat(pdf).hasSizeGreaterThan(1_000);
    assertThat(new String(pdf, 0, 5, StandardCharsets.ISO_8859_1)).isEqualTo("%PDF-");
  }

  @Test
  void reportsMissingTargetWithFixedChineseMessage() {
    when(targetService.get(7L)).thenThrow(new ApiException("授权目标不存在"));

    assertThatThrownBy(() -> service.generateHtml(7L))
        .isInstanceOf(ApiException.class)
        .hasMessage("授权目标不存在");
    verifyNoInteractions(taskRepository, findingRepository);
  }

  @Test
  void hidesPdfLibraryFailureFromApiMessage() {
    prepareData();
    String internalMessage = "底层 PDF 异常：password=secret";

    try (MockedStatic<PdfWriter> pdfWriter = mockStatic(PdfWriter.class)) {
      pdfWriter
          .when(() -> PdfWriter.getInstance(any(Document.class), any(OutputStream.class)))
          .thenThrow(new DocumentException(internalMessage));

      assertThatThrownBy(() -> service.generatePdf(7L))
          .isInstanceOf(ApiException.class)
          .hasMessage("PDF 报告生成失败，请稍后重试")
          .hasMessageNotContaining(internalMessage);
    }
  }

  private void prepareData() {
    AuthorizedTarget target = new AuthorizedTarget();
    target.setId(7L);
    target.setName("毕业设计项目");
    target.setTargetValue("https://example.test");
    target.setTargetType("URL");
    target.setAllowedPorts("443");
    target.setAuthorizationNote("仅限授权范围");
    target.setEnabled(true);
    target.setAuthorizationValidFrom(Instant.parse("2026-01-01T00:00:00Z"));
    target.setAuthorizationExpiresAt(Instant.parse("2026-12-31T00:00:00Z"));

    SecurityTask task = new SecurityTask();
    task.setId(11L);
    task.setTargetId(7L);
    task.setToolCode("NUCLEI_SCAN");
    task.setStatus("COMPLETED");
    task.setToolVersionSnapshot("nuclei 3.4.0");
    task.setRuleVersionSnapshot("rule-hash");
    task.setNucleiTemplateHashSnapshot("template-hash");

    Finding finding = new Finding();
    finding.setId(19L);
    finding.setTaskId(11L);
    finding.setTargetId(7L);
    finding.setTitle("漏洞<script>");
    finding.setSeverity("CRITICAL");
    finding.setSourceTool("NUCLEI_SCAN");
    finding.setStatus("OPEN");
    finding.setDescription("风险描述");
    finding.setRemediation("立即修复");

    when(targetService.get(7L)).thenReturn(target);
    when(taskRepository.findAllByTargetIdOrderByCreatedAtAsc(7L)).thenReturn(List.of(task));
    when(findingRepository.findAllByTargetIdOrderByCreatedAtAsc(7L)).thenReturn(List.of(finding));
  }
}
