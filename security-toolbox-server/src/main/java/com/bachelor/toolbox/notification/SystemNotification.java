package com.bachelor.toolbox.notification;

import jakarta.persistence.*;
import java.time.Instant;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(name = "system_notifications", indexes = @Index(name = "idx_notification_project", columnList = "projectId"))
@Getter
@Setter
@NoArgsConstructor
public class SystemNotification {
  @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;
  @Column(nullable = false, unique = true, length = 240)
  private String eventKey;
  private Long projectId;
  @Column(nullable = false)
  private boolean adminOnly;
  @Column(nullable = false, length = 40)
  private String category;
  @Column(nullable = false, length = 20)
  private String outcome;
  @Column(nullable = false, length = 180)
  private String title;
  @Column(nullable = false, length = 2000)
  private String body;
  @Column(nullable = false, length = 500)
  private String route;
  @Column(nullable = false, length = 200)
  private String severities;
  @Column(nullable = false, updatable = false)
  private Instant createdAt = Instant.now();
}
