package com.bachelor.toolbox.msf;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.bachelor.toolbox.common.ApiException;
import java.util.List;
import org.junit.jupiter.api.Test;

class MsfModuleOutputParserTests {
  private final MsfModuleOutputParser parser = new MsfModuleOutputParser();

  @Test
  void parsesOnlyAuxiliaryAndExploitModulesIntoStableLines() {
    String output =
        "auxiliary\tauxiliary/scanner/ssh/ssh_login\tSSH Login Check\tnormal\tChecks SSH credentials\n"
            + "exploit\texploit/multi/script/web_delivery\tWeb Delivery\tgreat\tServes payload\n"
            + "payload\tpayload/linux/x64/meterpreter_reverse_tcp\tMeterpreter\tmanual\tignored\n"
            + "post\tpost/linux/gather/env\tGather env\tnormal\tignored\n";

    List<MsfModuleOutputParser.MsfLine> lines = parser.parse(output);

    assertThat(lines).hasSize(2);
    assertThat(lines.get(0).modulePath()).isEqualTo("auxiliary/scanner/ssh/ssh_login");
    assertThat(lines.get(0).category()).isEqualTo("auxiliary");
    assertThat(lines.get(1).modulePath()).isEqualTo("exploit/multi/script/web_delivery");
  }

  @Test
  void rejectsIllegalModulePathContainingInjectionCharacters() {
    String output = "exploit\texploit/multi;rm -rf /\tbad\tnormal\tx\n";

    assertThatThrownBy(() -> parser.parse(output))
        .isInstanceOf(ApiException.class)
        .hasMessageContaining("模块");
  }

  @Test
  void blankOutputYieldsNoLines() {
    assertThat(parser.parse("   ")).isEmpty();
    assertThat(parser.parse(null)).isEmpty();
  }
}