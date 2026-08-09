package com.bachelor.toolbox.settings;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/settings")
public class SettingsController {
  private final BusinessDataResetService resetService;

  public SettingsController(BusinessDataResetService resetService) {
    this.resetService = resetService;
  }

  @DeleteMapping("/data")
  public BusinessDataResetService.ResetResult clearData(
      @Valid @RequestBody ClearDataRequest request) {
    return resetService.clear(request.confirmation());
  }

  public record ClearDataRequest(@NotBlank(message = "请输入 CLEAR 确认清空数据") String confirmation) {}
}
