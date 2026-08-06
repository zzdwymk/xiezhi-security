package com.bachelor.toolbox.report;

import java.nio.charset.StandardCharsets;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/reports/projects")
public class ProjectReportController {
  private static final MediaType HTML_UTF8 = new MediaType("text", "html", StandardCharsets.UTF_8);
  private final ProjectReportService reportService;
  private final ProjectReportSummaryService summaryService;
  private final ProjectAggregateReportService aggregateReportService;

  public ProjectReportController(
      ProjectReportService reportService,
      ProjectReportSummaryService summaryService,
      ProjectAggregateReportService aggregateReportService) {
    this.reportService = reportService;
    this.summaryService = summaryService;
    this.aggregateReportService = aggregateReportService;
  }

  @GetMapping("/{projectId}/summary")
  public ProjectReportSummaryService.Summary summary(@PathVariable Long projectId) {
    return summaryService.load(projectId);
  }

  /** Project-level report: aggregates every target belonging to the project. */
  @GetMapping(value = "/{projectId}.html", produces = "text/html;charset=UTF-8")
  public ResponseEntity<String> view(@PathVariable Long projectId) {
    return ResponseEntity.ok()
        .contentType(HTML_UTF8)
        .body(aggregateReportService.generateHtml(projectId));
  }

  /** Project-level PDF: aggregates every target belonging to the project. */
  @GetMapping(value = "/{projectId}.pdf", produces = MediaType.APPLICATION_PDF_VALUE)
  public ResponseEntity<byte[]> pdf(@PathVariable Long projectId) {
    ContentDisposition disposition =
        ContentDisposition.attachment()
            .filename("project-" + projectId + "-security-report.pdf", StandardCharsets.UTF_8)
            .build();
    return ResponseEntity.ok()
        .contentType(MediaType.APPLICATION_PDF)
        .header(HttpHeaders.CONTENT_DISPOSITION, disposition.toString())
        .body(aggregateReportService.generatePdf(projectId));
  }

  /** Backward-compatible target-level report endpoint. */
  @GetMapping(value = "/targets/{targetId}.html", produces = "text/html;charset=UTF-8")
  public ResponseEntity<String> targetHtml(@PathVariable Long targetId) {
    return ResponseEntity.ok().contentType(HTML_UTF8).body(reportService.generateHtml(targetId));
  }

  /** Backward-compatible target-level PDF endpoint. */
  @GetMapping(value = "/targets/{targetId}.pdf", produces = MediaType.APPLICATION_PDF_VALUE)
  public ResponseEntity<byte[]> targetPdf(@PathVariable Long targetId) {
    ContentDisposition disposition =
        ContentDisposition.attachment()
            .filename("target-" + targetId + "-security-report.pdf", StandardCharsets.UTF_8)
            .build();
    return ResponseEntity.ok()
        .contentType(MediaType.APPLICATION_PDF)
        .header(HttpHeaders.CONTENT_DISPOSITION, disposition.toString())
        .body(reportService.generatePdf(targetId));
  }
}
