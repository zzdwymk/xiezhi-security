package com.bachelor.toolbox.auth;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record ChangePasswordRequest(
    @NotBlank(message = "当前密码不能为空")
        @Size(max = 128, message = "当前密码长度不得超过 128 个字符") String currentPassword,
    @NotBlank(message = "新密码不能为空") @Size(min = 8, max = 128, message = "新密码长度需为 8-128 位")
        String newPassword) {
  @jakarta.validation.constraints.AssertTrue(message = "新密码的 UTF-8 编码不得超过 72 字节")
  public boolean isNewPasswordWithinBcryptByteLimit() {
    return newPassword == null
        || newPassword.getBytes(java.nio.charset.StandardCharsets.UTF_8).length <= 72;
  }
}
