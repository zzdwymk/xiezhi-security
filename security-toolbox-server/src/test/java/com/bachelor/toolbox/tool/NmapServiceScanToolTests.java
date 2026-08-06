package com.bachelor.toolbox.tool;

import static org.assertj.core.api.Assertions.assertThat;

import com.bachelor.toolbox.target.PortRangeParser;
import com.bachelor.toolbox.target.TargetPolicyService;
import java.util.List;
import org.junit.jupiter.api.Test;

class NmapServiceScanToolTests {
  private final NmapServiceScanTool tool =
      new NmapServiceScanTool(
          new TargetPolicyService(false, new PortRangeParser()),
          new PortRangeParser(),
          "nmap",
          65535,
          60,
          600);

  @Test
  void usesNmapFullRangeFlagInsteadOfEnumeratingPorts() {
    List<String> command = tool.buildCommand("127.0.0.1", "1-65535", "quick");

    assertThat(command).contains("-p-").doesNotContain("1-65535", "-p");
  }

  @Test
  void passesOtherSelectionsAsOneCompactRangeArgument() {
    List<String> command = tool.buildCommand("127.0.0.1", "80-82,443", "service");

    assertThat(command)
        .containsSubsequence("-sV", "--version-light")
        .containsSubsequence("--stats-every", "1s")
        .containsSubsequence("-p", "80-82,443");
  }
}
