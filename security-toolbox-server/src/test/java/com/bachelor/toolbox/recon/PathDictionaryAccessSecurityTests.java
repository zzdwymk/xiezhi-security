package com.bachelor.toolbox.recon;

import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anySet;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.bachelor.toolbox.auth.JwtService;
import com.bachelor.toolbox.auth.User;
import com.bachelor.toolbox.auth.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest(properties = {
    "spring.datasource.url=jdbc:h2:mem:path-dictionary-access;MODE=PostgreSQL;DB_CLOSE_DELAY=-1",
    "spring.jpa.hibernate.ddl-auto=create-drop",
    "toolbox.auth.allow-insecure-development-credentials=true",
    "toolbox.traffic.mitm-enabled=false",
    "toolbox.vulnerability-catalog.nuclei.import-on-startup=false",
    "toolbox.vulnerability-catalog.cisa-kev-enabled=false"
})
@AutoConfigureMockMvc
class PathDictionaryAccessSecurityTests {
  @Autowired MockMvc mvc;
  @Autowired UserRepository users;
  @Autowired JwtService jwt;
  @MockBean PathDictionaryService dictionary;

  @Test
  void regularUserCanReadButCannotMutateGlobalDictionary() throws Exception {
    mvc.perform(get("/api/recon/path-dictionary/library")).andExpect(status().isUnauthorized());
    User user = new User();
    user.setUsername("dictionary-regular-user");
    user.setPasswordHash("unused-test-hash");
    user.setRole("USER");
    String token = jwt.createToken(users.save(user));
    mvc.perform(get("/api/recon/path-dictionary/library").header("Authorization", "Bearer " + token))
        .andExpect(status().isOk());
    mvc.perform(post("/api/recon/path-dictionary/import").header("Authorization", "Bearer " + token)
        .contentType(MediaType.APPLICATION_JSON).content("{\"text\":\"qa-word\"}"))
        .andExpect(status().isForbidden());
    mvc.perform(post("/api/recon/path-dictionary/update").header("Authorization", "Bearer " + token)
        .contentType(MediaType.APPLICATION_JSON).content("{\"additions\":[],\"removals\":[]}"))
        .andExpect(status().isForbidden());
    verify(dictionary, never()).importText(anyString());
    verify(dictionary, never()).update(anyList(), anySet());
  }

  @Test
  void administratorCanReachMutationHandler() throws Exception {
    User admin = users.findByUsername("admin").orElseThrow();
    mvc.perform(post("/api/recon/path-dictionary/update").header("Authorization", "Bearer " + jwt.createToken(admin))
        .contentType(MediaType.APPLICATION_JSON).content("{\"additions\":[],\"removals\":[]}"))
        .andExpect(status().isOk());
    verify(dictionary).update(anyList(), anySet());
  }
}
