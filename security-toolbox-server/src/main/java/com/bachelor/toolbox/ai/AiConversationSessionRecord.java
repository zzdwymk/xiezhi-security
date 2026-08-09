package com.bachelor.toolbox.ai;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Lob;
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

  @Column(nullable = false)
  private Long projectId;

  @Column(nullable = false)
  private Long targetId;

  @Lob
  @Column(nullable = false)
  private String turnsJson;

  @Column(nullable = false)
  private Instant lastAccess;
}
