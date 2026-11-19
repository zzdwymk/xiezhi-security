package com.bachelor.toolbox.report;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;
import com.bachelor.toolbox.common.ApiException;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
class TaskReportResponseContractTests {
  @Test void previewAndDownloadKeepUtf8AndDifferentDispositions() {
    var service=mock(ReportService.class);when(service.generateTaskReport(7L)).thenReturn("<html>测试报告</html>");
    var controller=new ReportController(service);var view=controller.view(7L);var download=controller.download(7L);
    assertThat(view.getHeaders().getContentType().getCharset()).isEqualTo(StandardCharsets.UTF_8);
    assertThat(view.getHeaders().getFirst(HttpHeaders.CONTENT_DISPOSITION)).startsWith("inline;");
    assertThat(download.getHeaders().getFirst(HttpHeaders.CONTENT_DISPOSITION)).startsWith("attachment;");
    assertThat(download.getHeaders().getContentDisposition().getFilename()).isEqualTo("task-7-security-report.html");
    assertThat(view.getBody()).isEqualTo("<html>测试报告</html>");assertThat(download.getBody()).isEqualTo(view.getBody());
  }
  @Test void deniedReportGenerationCannotReturnSuccessfulBody() {
    var service=mock(ReportService.class);when(service.generateTaskReport(7L)).thenThrow(new ApiException("无权访问该评估项目"));
    var controller=new ReportController(service);
    assertThatThrownBy(()->controller.view(7L)).isInstanceOf(ApiException.class);
    assertThatThrownBy(()->controller.download(7L)).isInstanceOf(ApiException.class);
  }
}
