package com.bachelor.toolbox.tool;

import com.bachelor.toolbox.common.ApiException;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;

public class NmapXmlParser {
  public NmapParseResult parse(String xml) {
    try {
      String safeXml = removeKnownNmapPreamble(xml);
      DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
      factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
      factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
      factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
      factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
      factory.setXIncludeAware(false);
      factory.setExpandEntityReferences(false);
      factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
      factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");

      var document = factory.newDocumentBuilder().parse(new InputSource(new StringReader(safeXml)));
      List<Map<String, Object>> ports = new ArrayList<>();
      var nodes = document.getElementsByTagName("port");
      for (int i = 0; i < nodes.getLength(); i++) {
        Element port = (Element) nodes.item(i);
        Element state = first(port, "state");
        if (state == null || !"open".equalsIgnoreCase(state.getAttribute("state"))) continue;

        Element service = first(port, "service");
        Map<String, Object> item = new LinkedHashMap<>();
        item.put("port", Integer.parseInt(port.getAttribute("portid")));
        item.put("protocol", port.getAttribute("protocol"));
        item.put("state", "open");
        if (service != null) {
          put(item, "service", service.getAttribute("name"));
          put(item, "product", service.getAttribute("product"));
          put(item, "version", service.getAttribute("version"));
          put(item, "extraInfo", service.getAttribute("extrainfo"));
        }
        ports.add(item);
      }
      return new NmapParseResult(ports);
    } catch (ApiException ex) {
      throw ex;
    } catch (Exception ex) {
      throw new ApiException("无法安全解析 Nmap XML 输出");
    }
  }

  private String removeKnownNmapPreamble(String xml) {
    if (xml == null || xml.isBlank()) throw new ApiException("Nmap XML 输出为空");
    String normalized =
        xml.replaceFirst("(?is)<!DOCTYPE\\s+nmaprun\\s*>", "")
            .replaceAll("(?is)<\\?xml-stylesheet.*?\\?>", "");
    if (normalized.matches("(?is).*<!DOCTYPE.*") || normalized.matches("(?is).*<!ENTITY.*")) {
      throw new ApiException("Nmap XML 包含不允许的实体声明");
    }
    return normalized;
  }

  private Element first(Element parent, String tag) {
    var nodes = parent.getElementsByTagName(tag);
    return nodes.getLength() == 0 ? null : (Element) nodes.item(0);
  }

  private void put(Map<String, Object> target, String key, String value) {
    if (value != null && !value.isBlank()) target.put(key, value);
  }

  public record NmapParseResult(List<Map<String, Object>> openPorts) {}
}
