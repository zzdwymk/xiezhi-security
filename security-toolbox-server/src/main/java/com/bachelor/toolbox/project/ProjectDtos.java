package com.bachelor.toolbox.project;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import java.time.Instant;

public final class ProjectDtos {
  private ProjectDtos() {}

  public record Create(
      @NotBlank(message = "项目名称不能为空") @Size(max = 150, message = "项目名称长度不得超过 150 个字符") String name,
      @Size(max = 2000, message = "项目描述长度不得超过 2000 个字符") String description,
      @NotBlank(message = "授权声明不能为空") @Size(max = 4000, message = "授权声明长度不得超过 4000 个字符")
          String authorizationStatement,
      @NotNull(message = "授权开始时间不能为空") Instant authorizationValidFrom,
      @NotNull(message = "授权到期时间不能为空") Instant authorizationExpiresAt,
      @NotBlank(message = "项目负责人不能为空") @Size(max = 100, message = "项目负责人长度不得超过 100 个字符")
          String owner) {}

  public record Update(
      @Size(max = 150, message = "项目名称长度不得超过 150 个字符") String name,
      @Size(max = 2000, message = "项目描述长度不得超过 2000 个字符") String description,
      @Size(max = 4000, message = "授权声明长度不得超过 4000 个字符") String authorizationStatement,
      Instant authorizationValidFrom,
      Instant authorizationExpiresAt,
      String owner) {}

  public record Status(@NotBlank(message = "项目状态不能为空") String status) {}

  public record Summary(
      AssessmentProject project,
      long targetCount,
      long taskCount,
      long vulnerabilityCount,
      long informationalCount,
      long retestCount,
      long auditCount) {}
}
