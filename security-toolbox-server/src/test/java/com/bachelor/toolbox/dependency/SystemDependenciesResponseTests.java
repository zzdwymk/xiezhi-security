package com.bachelor.toolbox.dependency;

import static org.assertj.core.api.Assertions.assertThat;

import com.bachelor.toolbox.dependency.SystemDependenciesResponse.DependencyStatus;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import org.junit.jupiter.api.Test;

class SystemDependenciesResponseTests {
  private final ObjectMapper objectMapper = new ObjectMapper();

  @Test
  void preservesResponseJsonContract() {
    DependencyStatus dependency =
        new DependencyStatus(
            "Nmap",
            "AVAILABLE",
            "Nmap version 7.99",
            "C:\\tools\\nmap.exe",
            false,
            "SCANNER",
            "可用。");
    SystemDependenciesResponse response =
        new SystemDependenciesResponse("Windows 11", "amd64", List.of(dependency));

    JsonNode json = objectMapper.valueToTree(response);

    assertThat(json.size()).isEqualTo(3);
    assertThat(json.path("os").asText()).isEqualTo("Windows 11");
    assertThat(json.path("arch").asText()).isEqualTo("amd64");

    JsonNode item = json.path("dependencies").get(0);
    assertThat(item.size()).isEqualTo(7);
    assertThat(item.path("name").asText()).isEqualTo("Nmap");
    assertThat(item.path("status").asText()).isEqualTo("AVAILABLE");
    assertThat(item.path("version").asText()).isEqualTo("Nmap version 7.99");
    assertThat(item.path("path").asText()).isEqualTo("C:\\tools\\nmap.exe");
    assertThat(item.path("required").asBoolean()).isFalse();
    assertThat(item.path("category").asText()).isEqualTo("SCANNER");
    assertThat(item.path("message").asText()).isEqualTo("可用。");
  }
}
