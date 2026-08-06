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
@RequestMapping("/api/reports/tasks")
public class ReportController {
  private static final MediaType HTML_UTF8 = new MediaType("text", "html", StandardCharsets.UTF_8);

  private final ReportService reportService;

  public ReportController(ReportService reportService) {
    this.reportService = reportService;
  }

  @GetMapping(value = "/{taskId}.html", produces = "text/html;charset=UTF-8")
  public ResponseEntity<String> view(@PathVariable Long taskId) {
    return response(taskId, false);
  }

  @GetMapping(value = "/{taskId}/download", produces = "text/html;charset=UTF-8")
  public ResponseEntity<String> download(@PathVariable Long taskId) {
    return response(taskId, true);
  }

  private ResponseEntity<String> response(Long taskId, boolean attachment) {
    ContentDisposition disposition =
        ContentDisposition.builder(attachment ? "attachment" : "inline")
            .filename("task-" + taskId + "-security-report.html", StandardCharsets.UTF_8)
            .build();
    return ResponseEntity.ok()
        .contentType(HTML_UTF8)
        .header(HttpHeaders.CONTENT_DISPOSITION, disposition.toString())
        .body(reportService.generateTaskReport(taskId));
  }
}
