package com.bachelor.toolbox.asset;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import com.bachelor.toolbox.auth.*;
import com.bachelor.toolbox.project.*;
import com.bachelor.toolbox.target.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest(properties={
  "spring.datasource.url=jdbc:h2:mem:shared-target-path-isolation;MODE=PostgreSQL;DB_CLOSE_DELAY=-1",
  "spring.jpa.hibernate.ddl-auto=create-drop", "toolbox.auth.allow-insecure-development-credentials=true",
  "toolbox.traffic.mitm-enabled=false", "toolbox.vulnerability-catalog.nuclei.import-on-startup=false",
  "toolbox.vulnerability-catalog.cisa-kev-enabled=false"})
@AutoConfigureMockMvc
class SharedTargetPathIsolationTests {
  @Autowired MockMvc mvc;
  @Autowired UserRepository users;
  @Autowired JwtService jwt;
  @Autowired AssessmentProjectRepository projects;
  @Autowired ProjectTargetRepository links;
  @Autowired AuthorizedTargetRepository targets;
  @Autowired DiscoveredPathRepository paths;
  @Autowired ObjectMapper json;

  private AssessmentProject project(String owner) {
    var p=new AssessmentProject();p.setName("QA shared target");p.setOwner(owner);
    p.setAuthorizationStatement("Isolated test only");p.setAuthorizationValidFrom(Instant.now().minusSeconds(60));
    p.setAuthorizationExpiresAt(Instant.now().plusSeconds(600));return projects.saveAndFlush(p);
  }
  @Test void userSeesOnlyOwnedProjectPathsEvenWhenTargetIsShared() throws Exception {
    var user=new User();user.setUsername("shared-path-owner");user.setPasswordHash("unused");user.setRole("USER");users.saveAndFlush(user);
    var own=project(user.getUsername());var foreign=project("other-owner");
    var target=new AuthorizedTarget();target.setName("QA target");target.setTargetType("URL");
    target.setTargetValue("http://192.168.222.158");target.setAllowedPorts("80");target.setAuthorizationNote("test only");targets.saveAndFlush(target);
    links.saveAndFlush(new ProjectTarget(own.getId(),target.getId()));links.saveAndFlush(new ProjectTarget(foreign.getId(),target.getId()));
    paths.saveAndFlush(new DiscoveredPath(own.getId(),target.getId(),"http://192.168.222.158/own","/own","GET","QA",200,1L,null));
    paths.saveAndFlush(new DiscoveredPath(foreign.getId(),target.getId(),"http://192.168.222.158/private-foreign","/private-foreign","GET","QA",200,1L,"FOREIGN_PROJECT_EVIDENCE"));
    String endpoint="/api/targets/"+target.getId()+"/discovered-paths";
    mvc.perform(get(endpoint)).andExpect(status().isUnauthorized());
    String body=mvc.perform(get(endpoint).header("Authorization","Bearer "+jwt.createToken(user))).andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
    assertThat(json.readTree(body).size()).isEqualTo(1);
    assertThat(body).contains("/own").doesNotContain("private-foreign","FOREIGN_PROJECT_EVIDENCE");
    var admin=users.findByUsername("admin").orElseThrow();
    String all=mvc.perform(get(endpoint).header("Authorization","Bearer "+jwt.createToken(admin))).andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
    assertThat(json.readTree(all).size()).isEqualTo(2);
  }
}
