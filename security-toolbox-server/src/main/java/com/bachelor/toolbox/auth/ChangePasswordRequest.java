package com.bachelor.toolbox.auth;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record ChangePasswordRequest(
    @NotBlank(message = "当前密码不能为空") String currentPassword,
    @NotBlank(message = "新密码不能为空") @Size(min = 8, max = 128, message = "新密码长度需为 8-128 位")
        String newPassword) {}
