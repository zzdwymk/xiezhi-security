package com.bachelor.toolbox.tool;

import com.bachelor.toolbox.common.ApiException;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
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
      List<Map<String, Object>> openPorts = new ArrayList<>();
      List<Map<String, Object>> portStates = new ArrayList<>();
      List<Map<String, Object>> extraports = new ArrayList<>();
      List<Map<String, Object>> hostStatuses = new ArrayList<>();
      var hosts = document.getElementsByTagName("host");
      for (int i = 0; i < hosts.getLength(); i++) {
        Element host = (Element) hosts.item(i);
        String hostAddress = hostAddress(host);
        Element status = first(host, "status");
        if (status != null) {
          Map<String, Object> item = stateDetails(status);
          put(item, "hostAddress", hostAddress);
          hostStatuses.add(item);
        }
        Element ports = first(host, "ports");
        if (ports == null) continue;
        for (Element port : children(ports, "port")) {
          Element state = first(port, "state");
          Map<String, Object> item = state == null ? new LinkedHashMap<>() : stateDetails(state);
          int portId = Integer.parseInt(port.getAttribute("portid"));
          if (portId < 0 || portId > 65535) throw new ApiException("Nmap XML 端口号无效");
          item.put("port", portId);
          put(item, "protocol", port.getAttribute("protocol"));
          put(item, "hostAddress", hostAddress);
          Element service = first(port, "service");
          if (service != null) {
            put(item, "service", service.getAttribute("name"));
            put(item, "product", service.getAttribute("product"));
            put(item, "version", service.getAttribute("version"));
            put(item, "extraInfo", service.getAttribute("extrainfo"));
          }
          portStates.add(item);
          if ("open".equals(item.get("state"))) openPorts.add(new LinkedHashMap<>(item));
        }
        for (Element extra : children(ports, "extraports")) {
          Map<String, Object> item = new LinkedHashMap<>();
          put(item, "state", extra.getAttribute("state").toLowerCase(Locale.ROOT));
          putCount(item, "count", extra, "count");
          put(item, "hostAddress", hostAddress);
          List<Map<String, Object>> reasons = new ArrayList<>();
          for (Element reason : children(extra, "extrareasons")) {
            Map<String, Object> detail = new LinkedHashMap<>();
            put(detail, "reason", reason.getAttribute("reason"));
            putCount(detail, "count", reason, "count");
            put(detail, "protocol", reason.getAttribute("proto"));
            // A count alone does not identify ports. Preserve only explicit XML mappings.
            put(detail, "ports", reason.getAttribute("ports"));
            reasons.add(detail);
          }
          item.put("reasons", reasons);
          extraports.add(item);
        }
      }
      return new NmapParseResult(openPorts, portStates, extraports, hostStatuses);
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
    List<Element> matches = children(parent, tag);
    return matches.isEmpty() ? null : matches.get(0);
  }

  private List<Element> children(Element parent, String tag) {
    List<Element> matches = new ArrayList<>();
    var nodes = parent.getChildNodes();
    for (int i = 0; i < nodes.getLength(); i++) {
      if (nodes.item(i) instanceof Element child && tag.equals(child.getTagName())) {
        matches.add(child);
      }
    }
    return matches;
  }

  private String hostAddress(Element host) {
    for (Element address : children(host, "address")) {
      if (List.of("ipv4", "ipv6").contains(address.getAttribute("addrtype"))) {
        return address.getAttribute("addr");
      }
    }
    return "";
  }

  private Map<String, Object> stateDetails(Element state) {
    Map<String, Object> item = new LinkedHashMap<>();
    put(item, "state", state.getAttribute("state").toLowerCase(Locale.ROOT));
    put(item, "reason", state.getAttribute("reason"));
    put(item, "reasonIp", state.getAttribute("reason_ip"));
    putCount(item, "reasonTtl", state, "reason_ttl");
    return item;
  }

  private void putCount(Map<String, Object> target, String key, Element element, String attribute) {
    String raw = element.getAttribute(attribute);
    if (raw.isBlank()) return;
    int value = Integer.parseInt(raw);
    if (value < 0) throw new ApiException("Nmap XML 状态计数无效");
    target.put(key, value);
  }

  private void put(Map<String, Object> target, String key, String value) {
    if (value != null && !value.isBlank()) target.put(key, value);
  }

  public record NmapParseResult(
      List<Map<String, Object>> openPorts,
      List<Map<String, Object>> portStates,
      List<Map<String, Object>> extraports,
      List<Map<String, Object>> hostStatuses) {}
}
