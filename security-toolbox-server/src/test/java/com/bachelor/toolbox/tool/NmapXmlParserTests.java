package com.bachelor.toolbox.tool;

import static org.junit.jupiter.api.Assertions.*;

import com.bachelor.toolbox.common.ApiException;
import org.junit.jupiter.api.Test;

class NmapXmlParserTests {
  private final NmapXmlParser parser = new NmapXmlParser();

  @Test
  void parsesOnlyOpenPortsAndServiceDetails() {
    String xml =
        "<?xml version=\"1.0\"?><nmaprun><host><ports><port protocol=\"tcp\" portid=\"22\"><state"
            + " state=\"open\"/><service name=\"ssh\" product=\"OpenSSH\""
            + " version=\"9.0\"/></port><port protocol=\"tcp\" portid=\"80\"><state"
            + " state=\"closed\"/></port></ports></host></nmaprun>";
    var result = parser.parse(xml);
    assertEquals(1, result.openPorts().size());
    assertEquals(22, result.openPorts().get(0).get("port"));
    assertEquals("ssh", result.openPorts().get(0).get("service"));
    assertEquals("OpenSSH", result.openPorts().get(0).get("product"));
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
