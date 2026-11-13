package com.bachelor.toolbox.auth;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record LoginRequest(
    // Round 32：限制凭据长度，避免超大用户名/密码（≤32MB 请求体内）进入 findByUsername 的 DB 查询、
    // BCrypt 比对与 LoginAttemptService 的限流键，造成内存/DB 放大。上限与 ChangePasswordRequest 对齐。
    @NotBlank(message = "用户名不能为空") @Size(max = 100, message = "用户名长度不得超过 100 个字符")
        String username,
    @NotBlank(message = "密码不能为空") @Size(max = 128, message = "密码长度不得超过 128 个字符")
        String password) {}
