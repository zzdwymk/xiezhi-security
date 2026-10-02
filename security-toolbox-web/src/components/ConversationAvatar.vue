<script setup lang="ts">
import shield from "@fluentui/svg-icons/icons/shield_checkmark_24_regular.svg?url";
import person from "@fluentui/svg-icons/icons/person_24_regular.svg?url";

defineProps<{ role: string }>();
</script>

<template>
  <div class="conversation-avatar" :class="role" aria-hidden="true">
    <span
      class="avatar-glyph"
      :style="{ '--avatar-icon': `url(&quot;${role === 'assistant' ? shield : person}&quot;)` }"
    />
  </div>
</template>

<style scoped>
.conversation-avatar {
  display: grid;
  width: 34px;
  max-width: 100%;
  aspect-ratio: 1;
  box-sizing: border-box;
  place-items: center;
  align-self: start;
  border: 1px solid color-mix(in srgb, var(--app-accent) 24%, var(--app-border));
  border-radius: 11px;
  color: var(--app-accent);
  background: linear-gradient(
    145deg,
    color-mix(in srgb, var(--app-accent) 17%, var(--app-surface-strong)),
    color-mix(in srgb, var(--app-accent) 6%, var(--app-surface-strong))
  );
  box-shadow: 0 2px 5px color-mix(in srgb, var(--app-accent) 9%, transparent);
}
.conversation-avatar.user {
  border-color: var(--app-border);
  border-radius: 50%;
  color: var(--app-muted);
  background: var(--app-surface-soft);
  box-shadow: none;
}
.avatar-glyph {
  display: block;
  width: 21px;
  height: 21px;
  background: currentColor;
  -webkit-mask: var(--avatar-icon) center / contain no-repeat;
  mask: var(--avatar-icon) center / contain no-repeat;
}
@media (forced-colors: active) {
  .conversation-avatar {
    border-color: CanvasText;
    color: CanvasText;
    background: Canvas;
    box-shadow: none;
  }
}
</style>
