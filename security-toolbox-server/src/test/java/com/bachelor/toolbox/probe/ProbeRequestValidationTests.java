package com.bachelor.toolbox.probe;
import static org.assertj.core.api.Assertions.assertThat;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.validation.Validation;
import org.junit.jupiter.api.Test;
class ProbeRequestValidationTests {
 @Test void missingTargetIsRejectedByActualValidator() throws Exception {
  var request=new ObjectMapper().readValue("{\"url\":\"http://192.168.222.158/path\"}",ProbeRequest.class);
  try(var factory=Validation.buildDefaultValidatorFactory()){
   var violations=factory.getValidator().validate(request);
   assertThat(violations).hasSize(1);assertThat(violations.iterator().next().getPropertyPath().toString()).isEqualTo("targetId");
  }
 }
 @Test void routeSuppliedProjectMayRemainAbsentFromClientRequest() throws Exception {
  var request=new ObjectMapper().readValue("{\"targetId\":2,\"url\":\"http://192.168.222.158/path?x=1\"}",ProbeRequest.class);
  try(var factory=Validation.buildDefaultValidatorFactory()){assertThat(factory.getValidator().validate(request)).isEmpty();}
  assertThat(request.getProjectId()).isNull();assertThat(request.getUrl()).isEqualTo("http://192.168.222.158/path?x=1");
 }
}
