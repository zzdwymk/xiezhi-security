package com.bachelor.toolbox.tool;

import static org.assertj.core.api.Assertions.assertThat;

import com.bachelor.toolbox.dependency.NmapExecutableResolver;
import com.bachelor.toolbox.target.PortRangeParser;
import com.bachelor.toolbox.target.TargetPolicyService;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class NmapServiceScanToolTests {
  @TempDir Path tempDir;

  @Test
  void usesNmapFullRangeFlagInsteadOfEnumeratingPorts() throws Exception {
    NmapServiceScanTool tool = toolWithExecutable(createExecutable("nmap.exe"));
    List<String> command = tool.buildCommand("127.0.0.1", "1-65535", "quick");

    assertThat(command).contains("-p-").doesNotContain("1-65535", "-p");
  }

  @Test
  void passesOtherSelectionsAsOneCompactRangeArgument() throws Exception {
    NmapServiceScanTool tool = toolWithExecutable(createExecutable("nmap.exe"));
    List<String> command = tool.buildCommand("127.0.0.1", "80-82,443", "service");

    assertThat(command)
        .containsSubsequence("-sV", "--version-light")
        .containsSubsequence("--stats-every", "1s")
        .containsSubsequence("-p", "80-82,443");
  }

  @Test
  void resolvesConfiguredCommandNameBeforeCheckingExecutableFile() throws Exception {
    Path resolvedExecutable = createExecutable("nmap-from-path.exe");
    AtomicReference<List<String>> receivedCandidates = new AtomicReference<>();
    NmapExecutableResolver resolver =
        new NmapExecutableResolver(
            candidates -> {
              receivedCandidates.set(candidates);
              return Optional.of(resolvedExecutable);
            },
            "nmap");
    NmapServiceScanTool tool = tool(resolver);

    List<String> command = tool.buildCommand("127.0.0.1", "443", "quick");

    // configured "nmap" duplicates the first fallback, so the resolver deduplicates it.
    assertThat(receivedCandidates.get()).containsExactly("nmap", "nmap.exe");
    assertThat(command.get(0)).isEqualTo(resolvedExecutable.normalize().toString());
  }

  private NmapServiceScanTool toolWithExecutable(Path executable) {
    return tool(new NmapExecutableResolver(candidates -> Optional.of(executable), "nmap"));
  }

  private NmapServiceScanTool tool(NmapExecutableResolver resolver) {
    return new NmapServiceScanTool(
        new TargetPolicyService(false, new PortRangeParser()),
        new PortRangeParser(),
        resolver,
        65535,
        60,
        600);
  }

  private Path createExecutable(String name) throws Exception {
    return Files.createFile(tempDir.resolve(name));
  }
}
