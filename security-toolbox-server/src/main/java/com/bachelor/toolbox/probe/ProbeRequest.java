package com.bachelor.toolbox.probe;

import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
public class ProbeRequest {
  private Long projectId;

  @NotNull(message = "目标 ID 不能为空")
  private Long targetId;

  private String url;
}
