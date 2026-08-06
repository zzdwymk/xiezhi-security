package com.bachelor.toolbox.report;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

import com.bachelor.toolbox.common.ApiException;
import com.bachelor.toolbox.target.AuthorizedTargetRepository;
import com.lowagie.text.Document;
import com.lowagie.text.DocumentException;
import com.lowagie.text.pdf.PdfWriter;
import java.io.OutputStream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

class ProjectAggregateReportServiceTests {
  private ProjectReportSummaryService summaryService;
  private ProjectAggregateReportService service;

  @BeforeEach
  void setUp() {
    summaryService = mock(ProjectReportSummaryService.class);
    AuthorizedTargetRepository targetRepository = mock(AuthorizedTargetRepository.class);
    service = new ProjectAggregateReportService(summaryService, targetRepository);
  }

  @Test
  void hidesPdfLibraryFailureFromApiMessage() {
    ProjectReportSummaryService.Summary summary = mock(ProjectReportSummaryService.Summary.class);
    String internalMessage = "底层项目 PDF 异常：token=secret";
    when(summaryService.load(9L)).thenReturn(summary);

    try (MockedStatic<PdfWriter> pdfWriter = mockStatic(PdfWriter.class)) {
      pdfWriter
          .when(() -> PdfWriter.getInstance(any(Document.class), any(OutputStream.class)))
          .thenThrow(new DocumentException(internalMessage));

      assertThatThrownBy(() -> service.generatePdf(9L))
          .isInstanceOf(ApiException.class)
          .hasMessage("项目 PDF 报告生成失败，请稍后重试")
          .hasMessageNotContaining(internalMessage);
    }
  }
}
