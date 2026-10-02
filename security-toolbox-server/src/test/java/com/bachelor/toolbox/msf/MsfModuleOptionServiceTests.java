package com.bachelor.toolbox.msf;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.bachelor.toolbox.common.ApiException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class MsfModuleOptionServiceTests {
  private static final String MODULE = "auxiliary/scanner/http/http_header";
  private final MsfModuleOptionService service = new MsfModuleOptionService(
      candidates -> Optional.empty(), new ObjectMapper(), "msfconsole", 60);

  @Test
  void parsesActualLocalInfoJsonAndFiltersServerBoundOptions() throws Exception {
    // Captured from the installed framework using only: info -j <module>; exit.
    String json;
    try (var input = getClass().getResourceAsStream("/msf/http-header-info.json")) {
      assertThat(input).isNotNull();
      json = new String(input.readAllBytes(), StandardCharsets.UTF_8);
    }
    var options = service.parse(MODULE, "Ruby startup warning\n\u001b[32m" + json + "\u001b[0m");
    assertThat(options).hasSize(7);
    assertThat(options).extracting(MsfModuleOptionService.ModuleOption::name).doesNotContain("RHOSTS", "RPORT");
    var method = options.stream().filter(o -> o.name().equals("HTTP_METHOD")).findFirst().orElseThrow();
    assertThat(method.defaultValue()).isEqualTo("HEAD");
    assertThat(method.required()).isTrue();
    assertThat(method.type()).isNull(); // The real serializer does not provide a type.
    assertThat(method.description()).contains("GET, HEAD");
    assertThat(options.stream().filter(o -> o.name().equals("TARGETURI")).findFirst().orElseThrow().defaultValue()).isEqualTo("/");
    assertThat(options.stream().filter(o -> o.name().equals("SSL")).findFirst().orElseThrow().defaultValue()).isEqualTo("false");
  }

  @Test
  void acceptsLegacyObjectOptionsAndExplicitEmptyCollections() {
    String options = "{\"HTTP_METHOD\":{\"type\":\"string\",\"required\":true,\"default\":\"HEAD\",\"desc\":\"Method\"},"
        + "\"rhosts\":{\"required\":true,\"default\":\"\"}}";
    assertThat(service.parse(MODULE, options)).hasSize(1);
    assertThat(service.parse(MODULE, "{\"options\":" + options + "}")).hasSize(1);
    assertThat(service.parse(MODULE, "{\"options\":[]}")).isEmpty();
    assertThat(service.parse(MODULE, "{\"options\":{}}")).isEmpty();
  }

  @Test
  void rejectsUnknownSchemasRatherThanClaimingNoConfigurationNeeded() {
    for (String output : new String[] {"ERROR: Invalid command line option provided.", "{}",
        "{\"name\":\"module\"}", "{\"options\":false}", "{\"options\":[{}]}",
        "{\"options\":{\"name\":\"HEAD\"}}",
        "{\"options\":[{\"name\":\"X\",\"display_value\":\"\",\"required\":\"unknown\",\"description\":\"x\"}]}"}) {
      assertThatThrownBy(() -> service.parse(MODULE, output)).isInstanceOf(ApiException.class);
    }
  }
}
