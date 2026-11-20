package com.bachelor.toolbox.common;
import static org.assertj.core.api.Assertions.assertThat;
import org.junit.jupiter.api.Test;
class PublicBusinessErrorPrivacyTests {
 @Test void chineseMessagesWithSecretsOrInternalPathsAreNotReturned(){
  var handler=new GlobalExceptionHandler();
  for(String message:new String[]{"处理失败 token=QA_SECRET","读取失败 C:/private/qa.json","失败 Authorization: Bearer QA_SECRET"}) {
   assertThat(handler.handleIllegalArgument(new IllegalArgumentException(message)).getBody().message()).isEqualTo("请求参数不合法");
   assertThat(handler.handleApi(new ApiException(message),null,null).getBody().message()).isEqualTo("请求处理失败");
  }
 }
 @Test void normalGuidanceRemainsButHugeDiagnosticsAreHidden(){
  var handler=new GlobalExceptionHandler();
  assertThat(handler.handleIllegalArgument(new IllegalArgumentException("目标授权已过期")).getBody().message()).isEqualTo("目标授权已过期");
  assertThat(handler.handleIllegalArgument(new IllegalArgumentException("错误"+"a".repeat(3000))).getBody().message()).isEqualTo("请求参数不合法");
 }
}
