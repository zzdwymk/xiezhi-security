package com.bachelor.toolbox.report;
import static org.assertj.core.api.Assertions.assertThat;
import org.jsoup.Jsoup;
import org.junit.jupiter.api.Test;
class ReportMarkdownBoundaryTests {
 @Test void scriptsEventsAndActiveMediaNeverSurviveSanitizing(){
  var doc=Jsoup.parseBodyFragment(ReportMarkdown.render("<script>window.qa=1</script><img src=x onerror=alert(1)><iframe src='https://example.test'></iframe><p onclick='alert(1)'>safe</p>\n\n[x](javascript:alert%281%29)"));
  assertThat(doc.select("script,img,iframe,svg,object")).isEmpty();
  assertThat(doc.select("[onclick],[onerror]")).isEmpty();
  for(var link:doc.select("a")) assertThat(link.attr("href")).doesNotStartWith("javascript:");
 }
 @Test void externalLinksAreIsolatedAndFragmentLinksRemainLocal(){
  var doc=Jsoup.parseBodyFragment(ReportMarkdown.render("[external](https://example.test/path) [local](#section)"));
  var external=doc.selectFirst("a[href^=https]");assertThat(external).isNotNull();
  assertThat(external.attr("target")).isEqualTo("_blank");assertThat(external.attr("rel")).isEqualTo("noopener noreferrer");
  assertThat(doc.select("a[href='#section']")).hasSize(1);
 }
 @Test void fencedCommandEvidenceIsNotLocalizedOrExecuted(){
  var doc=Jsoup.parseBodyFragment(ReportMarkdown.render("```text\nhttp_headers --status SUCCESS <script>QA</script>\n```"));
  assertThat(doc.selectFirst("pre code").text()).contains("http_headers --status SUCCESS <script>QA</script>");
  assertThat(doc.select("script")).isEmpty();
 }
}
