package com.bachelor.toolbox.notification;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/notifications")
public class NotificationController {
  private final NotificationService notifications;
  public NotificationController(NotificationService notifications) { this.notifications = notifications; }

  @GetMapping
  public NotificationService.Feed list(@RequestParam(required = false) Long after,
      @RequestParam(defaultValue = "100") int limit) {
    return notifications.feed(after, limit);
  }
}
