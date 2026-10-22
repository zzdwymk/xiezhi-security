package com.bachelor.toolbox.ai;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@Entity
@Table(name = "ai_conversation_sessions")
public class AiConversationSessionRecord {
  @Id
  @Column(length = 64)
  private String id;

  @Column(length = 255)
  private String title;

  @Column
  private Long projectId;

  @Column
  private Long targetId;

  @Column(length = 255)
  private String targetName;

  @Column(columnDefinition = "TEXT")
  private String threadJson;

  @Column(nullable = false, columnDefinition = "TEXT")
  private String turnsJson;

  // Nullable for existing profiles. Only server-validated, successfully delivered plans belong here.
  @Column(columnDefinition = "TEXT")
  private String lastPlanJson;

  // Bounded, prompt-free aggregate model usage snapshot.
  @Column(columnDefinition = "TEXT")
  private String usageJson;

  // Structured digest of turns a long conversation compressed away. Nullable: absent until the
  // runtime first compacts, and safe to lose (it only affects context recall, never authority).
  @Column(columnDefinition = "TEXT")
  private String summaryJson;

  @Column
  private Instant createdAt;

  @Column(nullable = false)
  private Instant lastAccess;
}
