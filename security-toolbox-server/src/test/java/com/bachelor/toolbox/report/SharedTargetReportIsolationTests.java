package com.bachelor.toolbox.report;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import com.bachelor.toolbox.auth.*;
import com.bachelor.toolbox.project.*;
import com.bachelor.toolbox.target.*;
import com.bachelor.toolbox.task.*;
import com.bachelor.toolbox.finding.*;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
@SpringBootTest(properties={"spring.datasource.url=jdbc:h2:mem:shared-target-report;MODE=PostgreSQL;DB_CLOSE_DELAY=-1","spring.jpa.hibernate.ddl-auto=create-drop","toolbox.auth.allow-insecure-development-credentials=true","toolbox.traffic.mitm-enabled=false","toolbox.vulnerability-catalog.nuclei.import-on-startup=false","toolbox.vulnerability-catalog.cisa-kev-enabled=false"})
@AutoConfigureMockMvc
class SharedTargetReportIsolationTests {
 @Autowired MockMvc mvc; @Autowired UserRepository users; @Autowired JwtService jwt;
 @Autowired AssessmentProjectRepository projects; @Autowired ProjectTargetRepository links;
 @Autowired AuthorizedTargetRepository targets; @Autowired SecurityTaskRepository tasks; @Autowired FindingRepository findings;
 private AssessmentProject project(String owner){var p=new AssessmentProject();p.setName("QA report");p.setOwner(owner);p.setAuthorizationStatement("Test only");p.setAuthorizationValidFrom(Instant.now().minusSeconds(60));p.setAuthorizationExpiresAt(Instant.now().plusSeconds(600));return projects.saveAndFlush(p);}
 private void finding(AssessmentProject p,AuthorizedTarget target,String title){var t=new SecurityTask();t.setProjectId(p.getId());t.setTargetId(target.getId());t.setToolCode("http_headers");t.setStatus("SUCCESS");tasks.saveAndFlush(t);var f=new Finding();f.setTaskId(t.getId());f.setTargetId(target.getId());f.setTitle(title);f.setSeverity("HIGH");f.setSourceTool("QA");findings.saveAndFlush(f);}
 @Test void sharedTargetReportDoesNotExposeForeignProjectFindings() throws Exception {
  var u=new User();u.setUsername("report-owner");u.setPasswordHash("unused");u.setRole("USER");users.saveAndFlush(u);
  var own=project(u.getUsername());var foreign=project("foreign-owner");var target=new AuthorizedTarget();target.setName("QA shared");target.setTargetValue("http://192.168.222.158");target.setTargetType("URL");target.setAuthorizationNote("Test only");targets.saveAndFlush(target);
  links.saveAndFlush(new ProjectTarget(own.getId(),target.getId()));links.saveAndFlush(new ProjectTarget(foreign.getId(),target.getId()));finding(own,target,"OWN_REPORT_MARKER");finding(foreign,target,"FOREIGN_REPORT_MARKER");
  String url="/api/reports/projects/targets/"+target.getId()+".html";
  mvc.perform(get(url).header("Authorization","Bearer "+jwt.createToken(u))).andExpect(status().isForbidden());
  mvc.perform(get(url.replace(".html", ".pdf")).header("Authorization","Bearer "+jwt.createToken(u))).andExpect(status().isForbidden());
  mvc.perform(get("/api/reports/projects/"+own.getId()+"/summary").header("Authorization","Bearer "+jwt.createToken(u))).andExpect(status().isForbidden());
  mvc.perform(get(url)).andExpect(status().isUnauthorized());
  var admin=users.findByUsername("admin").orElseThrow();String all=mvc.perform(get(url).header("Authorization","Bearer "+jwt.createToken(admin))).andExpect(status().isOk()).andReturn().getResponse().getContentAsString();assertThat(all).contains("OWN_REPORT_MARKER","FOREIGN_REPORT_MARKER");
 }
}
