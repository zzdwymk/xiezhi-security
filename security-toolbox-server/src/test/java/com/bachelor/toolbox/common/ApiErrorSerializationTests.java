package com.bachelor.toolbox.common;
import static org.assertj.core.api.Assertions.assertThat;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.util.HashSet;
import org.junit.jupiter.api.Test;
class ApiErrorSerializationTests {
 @Test void jsonContractContainsOnlyTimestampStatusAndMessage() throws Exception {
  Instant before=Instant.now();var response=ApiErrorResponse.of(400,"请求参数不合法");
  assertThat(response.timestamp()).isBetween(before,Instant.now());
  var json=new ObjectMapper().findAndRegisterModules().valueToTree(response);
  var fields=new HashSet<String>();json.fieldNames().forEachRemaining(fields::add);
  assertThat(fields).containsExactlyInAnyOrder("timestamp","status","message");
  assertThat(json.path("status").asInt()).isEqualTo(400);assertThat(json.path("message").asText()).isEqualTo("请求参数不合法");
 }
}
