package com.bachelor.toolbox.common;
import static org.assertj.core.api.Assertions.assertThat;
import java.util.List;
import org.junit.jupiter.api.Test;
class ProcessSecretInheritanceTests {
 @Test void databaseDesktopAndShutdownSecretsAreNotInherited(){
  var builder=new ProcessBuilder("qa-not-executed");
  var keys=List.of("DB_PASSWORD","TOOLBOX_DESKTOP_SEED_ADMIN_PASSWORD","TOOLBOX_SHUTDOWN_TOKEN");
  for(String key:keys)builder.environment().put(key,"QA_ONLY_SECRET");
  builder.environment().put("PATH","QA_SAFE_PATH");
  ProcessEnvironmentSanitizer.sanitize(builder);
  for(String key:keys)assertThat(builder.environment()).doesNotContainKey(key);
  assertThat(builder.environment().get("PATH")).isEqualTo("QA_SAFE_PATH");
 }
}
