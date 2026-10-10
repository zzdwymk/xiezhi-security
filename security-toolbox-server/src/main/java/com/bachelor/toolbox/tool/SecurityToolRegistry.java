package com.bachelor.toolbox.tool;

import com.bachelor.toolbox.common.ApiException;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Component;

@Component
public class SecurityToolRegistry {
  private final Map<String, SecurityTool> tools = new LinkedHashMap<>();

  public SecurityToolRegistry(List<SecurityTool> toolList) {
    for (SecurityTool tool : toolList) {
      if (tool.code() == null || tool.code().isBlank()) {
        throw new IllegalStateException("安全工具注册 code 不能为空");
      }
      if (tools.putIfAbsent(tool.code(), tool) != null) {
        throw new IllegalStateException("安全工具 code 重复注册: " + tool.code());
      }
    }
  }

  public SecurityTool require(String code) {
    SecurityTool tool = tools.get(code);
    if (tool == null) {
      throw new ApiException("未知或未授权的工具: " + code);
    }
    return tool;
  }

  public Collection<SecurityTool> all() {
    return tools.values();
  }
}
