package com.bachelor.toolbox.ai;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.test.util.ReflectionTestUtils;

class AiRuntimeUnicodeDigestTests {
  static Stream<Arguments> pythonVectors() throws Exception {
    var mapper = new ObjectMapper();
    try (var input = AiRuntimeUnicodeDigestTests.class.getResourceAsStream("/ai-runtime-unicode-digests.json")) {
      var builder = Stream.<Arguments>builder();
      for (JsonNode vector : mapper.readTree(input)) builder.add(Arguments.of(vector.path("name").asText(), vector));
      return builder.build();
    }
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("pythonVectors")
  void candidateDigestMatchesIndependentPythonUtf8Vector(String name, JsonNode vector) throws Exception {
    var mapper = new ObjectMapper();
    var client = new AiAgentRuntimeClient(mapper, null, null, null, null, false,
        "http://127.0.0.1:1", 1, "", "", 10, 1);
    var event = mapper.treeToValue(vector.get("event"), AiAgentRuntimeClient.RuntimeEvent.class);
    String actual = ReflectionTestUtils.invokeMethod(client, "runtimeEventDigest", event,
        vector.path("previousDigest").asText());
    assertThat(actual).isEqualTo(vector.path("expected").asText());
  }
}
