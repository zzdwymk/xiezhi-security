package com.bachelor.toolbox.tool;

import static org.junit.jupiter.api.Assertions.*;

import com.bachelor.toolbox.common.ApiException;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class NmapXmlParserTests {
  private final NmapXmlParser parser = new NmapXmlParser();

  @Test
  void preservesOpenPortsCompatibilityAndAllExplicitStates() {
    String xml =
        """
        <nmaprun><host><status state="up" reason="user-set" reason_ttl="0"/>
          <address addr="127.0.0.1" addrtype="ipv4"/><ports>
            <port protocol="tcp" portid="22"><state state="open" reason="syn-ack" reason_ttl="64"/>
              <service name="ssh" product="OpenSSH" version="9.0"/></port>
            <port protocol="tcp" portid="80"><state state="closed" reason="conn-refused"/></port>
            <port protocol="tcp" portid="443"><state state="filtered" reason="no-response"/></port>
          </ports></host></nmaprun>
        """;
    var result = parser.parse(xml);
    assertEquals(1, result.openPorts().size());
    assertEquals(22, result.openPorts().get(0).get("port"));
    assertEquals("ssh", result.openPorts().get(0).get("service"));
    assertEquals("OpenSSH", result.openPorts().get(0).get("product"));
    assertEquals(List.of("open", "closed", "filtered"),
        result.portStates().stream().map(item -> item.get("state")).toList());
    assertEquals(List.of(22, 80, 443),
        result.portStates().stream().map(item -> item.get("port")).toList());
    assertEquals("conn-refused", result.portStates().get(1).get("reason"));
    assertEquals("no-response", result.portStates().get(2).get("reason"));
    assertEquals(64, result.portStates().get(0).get("reasonTtl"));
    assertEquals(Map.of("state", "up", "reason", "user-set", "reasonTtl", 0,
        "hostAddress", "127.0.0.1"), result.hostStatuses().get(0));
  }

  @Test
  void retainsAggregateStatesWithoutInventingIndividualPortMappings() {
    var result = parser.parse("""
        <nmaprun><host><ports>
          <port protocol="tcp" portid="22"><state state="open"/></port>
          <extraports state="closed" count="98"><extrareasons reason="reset" count="98"/></extraports>
          <extraports state="filtered" count="1"><extrareasons reason="no-response" count="1"/></extraports>
        </ports></host></nmaprun>
        """);

    assertEquals(1, result.portStates().size());
    assertEquals(22, result.portStates().get(0).get("port"));
    assertEquals(List.of(
        Map.of("state", "closed", "count", 98,
            "reasons", List.of(Map.of("reason", "reset", "count", 98))),
        Map.of("state", "filtered", "count", 1,
            "reasons", List.of(Map.of("reason", "no-response", "count", 1)))), result.extraports());
  }

  @Test
  void preservesOnlyExplicitAggregatePortMappingsAndHostIdentity() {
    var result = parser.parse("""
        <nmaprun><host><address addr="::1" addrtype="ipv6"/><ports>
          <extraports state="closed" count="3">
            <extrareasons reason="conn-refused" count="3" proto="tcp" ports="80-81,443"/>
          </extraports>
        </ports></host></nmaprun>
        """);

    assertTrue(result.portStates().isEmpty());
    assertTrue(result.openPorts().isEmpty());
    assertEquals(Map.of("state", "closed", "count", 3, "hostAddress", "::1",
        "reasons", List.of(Map.of("reason", "conn-refused", "count", 3,
            "protocol", "tcp", "ports", "80-81,443"))), result.extraports().get(0));
  }

  @Test
  void preservesAmbiguousStatesAndDoesNotInventMissingStates() {
    var result = parser.parse("""
        <nmaprun><host><ports>
          <port protocol="udp" portid="53"><state state="open|filtered" reason="no-response"/></port>
          <port protocol="tcp" portid="80"><state state="unfiltered"/></port>
          <port protocol="tcp" portid="443"/>
        </ports></host></nmaprun>
        """);

    assertTrue(result.openPorts().isEmpty());
    assertEquals("open|filtered", result.portStates().get(0).get("state"));
    assertEquals("unfiltered", result.portStates().get(1).get("state"));
    assertEquals(Map.of("protocol", "tcp", "port", 443), result.portStates().get(2));
  }

  @Test
  void keepsHostDownEvidenceWithoutFabricatingPorts() {
    var result = parser.parse("""
        <nmaprun><host><status state="down" reason="no-response"/>
          <address addr="192.0.2.1" addrtype="ipv4"/></host></nmaprun>
        """);

    assertTrue(result.openPorts().isEmpty());
    assertTrue(result.portStates().isEmpty());
    assertTrue(result.extraports().isEmpty());
    assertEquals(Map.of("state", "down", "reason", "no-response", "hostAddress", "192.0.2.1"),
        result.hostStatuses().get(0));
  }

  @Test
  void rejectsInvalidPortNumbersAndNegativeCounts() {
    assertThrows(ApiException.class, () -> parser.parse("""
        <nmaprun><host><ports><port portid="65536"><state state="closed"/></port></ports></host></nmaprun>
        """));
    assertThrows(ApiException.class, () -> parser.parse("""
        <nmaprun><host><ports><extraports state="closed" count="-1"/></ports></host></nmaprun>
        """));
  }

  @Test
  void acceptsStandardNmapDoctypeAndStylesheet() {
    String xml =
        "<?xml version=\"1.0\"?><!DOCTYPE nmaprun><?xml-stylesheet href=\"file:///nmap.xsl\""
            + " type=\"text/xsl\"?><nmaprun><host><ports><port protocol=\"tcp\""
            + " portid=\"8081\"><state state=\"open\"/><service name=\"http\""
            + " product=\"SimpleHTTPServer\"/></port></ports></host></nmaprun>";
    var result = parser.parse(xml);
    assertEquals(1, result.openPorts().size());
    assertEquals(8081, result.openPorts().get(0).get("port"));
  }

  @Test
  void rejectsDoctypeAndExternalEntities() {
    String xml = "<!DOCTYPE x [<!ENTITY e SYSTEM \"file:///etc/passwd\">]><nmaprun>&e;</nmaprun>";
    assertThrows(ApiException.class, () -> parser.parse(xml));
  }
}
