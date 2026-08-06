<script setup lang="ts">
import { computed } from "vue";
import add from "@fluentui/svg-icons/icons/add_24_regular.svg?url";
import arrowBidirectional from "@fluentui/svg-icons/icons/arrow_bidirectional_up_down_24_regular.svg?url";
import arrowClockwise from "@fluentui/svg-icons/icons/arrow_clockwise_24_regular.svg?url";
import arrowDownload from "@fluentui/svg-icons/icons/arrow_download_24_regular.svg?url";
import arrowReset from "@fluentui/svg-icons/icons/arrow_reset_24_regular.svg?url";
import arrowSwap from "@fluentui/svg-icons/icons/arrow_swap_24_regular.svg?url";
import arrowUpload from "@fluentui/svg-icons/icons/arrow_upload_24_regular.svg?url";
import beaker from "@fluentui/svg-icons/icons/beaker_24_regular.svg?url";
import book from "@fluentui/svg-icons/icons/book_information_24_regular.svg?url";
import branchFork from "@fluentui/svg-icons/icons/branch_fork_24_regular.svg?url";
import chart from "@fluentui/svg-icons/icons/chart_multiple_24_regular.svg?url";
import chat from "@fluentui/svg-icons/icons/chat_24_regular.svg?url";
import checkmark from "@fluentui/svg-icons/icons/checkmark_24_regular.svg?url";
import checkmarkCircle from "@fluentui/svg-icons/icons/checkmark_circle_24_regular.svg?url";
import chevronDown from "@fluentui/svg-icons/icons/chevron_down_24_regular.svg?url";
import chevronRight from "@fluentui/svg-icons/icons/chevron_right_24_regular.svg?url";
import chevronUp from "@fluentui/svg-icons/icons/chevron_up_24_regular.svg?url";
import clipboardTask from "@fluentui/svg-icons/icons/clipboard_task_list_ltr_24_regular.svg?url";
import clipboardText from "@fluentui/svg-icons/icons/clipboard_text_ltr_24_regular.svg?url";
import clock from "@fluentui/svg-icons/icons/clock_24_regular.svg?url";
import copy from "@fluentui/svg-icons/icons/copy_24_regular.svg?url";
import dataBar from "@fluentui/svg-icons/icons/data_bar_vertical_24_regular.svg?url";
import deleteIcon from "@fluentui/svg-icons/icons/delete_24_regular.svg?url";
import dismiss from "@fluentui/svg-icons/icons/dismiss_24_regular.svg?url";
import document from "@fluentui/svg-icons/icons/document_24_regular.svg?url";
import documentCheckmark from "@fluentui/svg-icons/icons/document_checkmark_24_regular.svg?url";
import documentMultiple from "@fluentui/svg-icons/icons/document_multiple_24_regular.svg?url";
import documentText from "@fluentui/svg-icons/icons/document_text_24_regular.svg?url";
import edit from "@fluentui/svg-icons/icons/edit_24_regular.svg?url";
import eye from "@fluentui/svg-icons/icons/eye_24_regular.svg?url";
import filter from "@fluentui/svg-icons/icons/filter_24_regular.svg?url";
import flag from "@fluentui/svg-icons/icons/flag_24_regular.svg?url";
import fit from "@fluentui/svg-icons/icons/full_screen_maximize_24_regular.svg?url";
import folder from "@fluentui/svg-icons/icons/folder_24_regular.svg?url";
import folderOpen from "@fluentui/svg-icons/icons/folder_open_24_regular.svg?url";
import globe from "@fluentui/svg-icons/icons/globe_24_regular.svg?url";
import globeSearch from "@fluentui/svg-icons/icons/globe_search_24_regular.svg?url";
import homeFilled from "@fluentui/svg-icons/icons/home_24_filled.svg?url";
import key from "@fluentui/svg-icons/icons/key_24_regular.svg?url";
import location from "@fluentui/svg-icons/icons/location_24_regular.svg?url";
import lockClosed from "@fluentui/svg-icons/icons/lock_closed_24_regular.svg?url";
import map from "@fluentui/svg-icons/icons/map_24_regular.svg?url";
import numberSymbol from "@fluentui/svg-icons/icons/number_symbol_24_regular.svg?url";
import pause from "@fluentui/svg-icons/icons/pause_24_regular.svg?url";
import play from "@fluentui/svg-icons/icons/play_24_regular.svg?url";
import plug from "@fluentui/svg-icons/icons/plug_connected_24_regular.svg?url";
import questionCircle from "@fluentui/svg-icons/icons/question_circle_24_regular.svg?url";
import rocket from "@fluentui/svg-icons/icons/rocket_24_regular.svg?url";
import search from "@fluentui/svg-icons/icons/search_24_regular.svg?url";
import send from "@fluentui/svg-icons/icons/send_24_regular.svg?url";
import server from "@fluentui/svg-icons/icons/server_24_regular.svg?url";
import settings from "@fluentui/svg-icons/icons/settings_24_regular.svg?url";
import shield from "@fluentui/svg-icons/icons/shield_24_regular.svg?url";
import shieldCheckmark from "@fluentui/svg-icons/icons/shield_checkmark_24_regular.svg?url";
import shieldTask from "@fluentui/svg-icons/icons/shield_task_24_regular.svg?url";
import signOut from "@fluentui/svg-icons/icons/sign_out_24_regular.svg?url";
import sparkle from "@fluentui/svg-icons/icons/sparkle_24_regular.svg?url";
import star from "@fluentui/svg-icons/icons/star_24_regular.svg?url";
import starFilled from "@fluentui/svg-icons/icons/star_24_filled.svg?url";
import subtract from "@fluentui/svg-icons/icons/subtract_24_regular.svg?url";
import sync from "@fluentui/svg-icons/icons/arrow_sync_24_regular.svg?url";
import target from "@fluentui/svg-icons/icons/target_24_regular.svg?url";
import warning from "@fluentui/svg-icons/icons/warning_24_regular.svg?url";
import wrench from "@fluentui/svg-icons/icons/wrench_24_regular.svg?url";

const iconUrls: Record<string, string> = {
  add,
  "arrow-bidirectional": arrowBidirectional,
  "arrow-clockwise": arrowClockwise,
  "arrow-download": arrowDownload,
  "arrow-reset": arrowReset,
  "arrow-right": chevronRight,
  "arrow-swap": arrowSwap,
  "arrow-upload": arrowUpload,
  beaker,
  book,
  "branch-fork": branchFork,
  chart,
  chat,
  checkmark,
  "checkmark-circle": checkmarkCircle,
  "chevron-down": chevronDown,
  "chevron-right": chevronRight,
  "chevron-up": chevronUp,
  "clipboard-task": clipboardTask,
  "clipboard-text": clipboardText,
  clock,
  copy,
  data: dataBar,
  delete: deleteIcon,
  dismiss,
  document,
  "document-checkmark": documentCheckmark,
  "document-multiple": documentMultiple,
  report: documentText,
  edit,
  eye,
  filter,
  flag,
  fit,
  folder,
  "folder-open": folderOpen,
  globe,
  "globe-search": globeSearch,
  home: homeFilled,
  key,
  location,
  lock: lockClosed,
  map,
  hash: numberSymbol,
  pause,
  play,
  plug,
  question: questionCircle,
  rocket,
  search,
  send,
  server,
  settings,
  shield,
  "shield-checkmark": shieldCheckmark,
  "shield-task": shieldTask,
  "sign-out": signOut,
  sparkle,
  star,
  "star-filled": starFilled,
  subtract,
  sync,
  target,
  warning,
  wrench,
};

const props = defineProps<{
  name: string;
  label?: string;
}>();

const iconUrl = computed(() => iconUrls[props.name] || questionCircle);
const maskStyle = computed(() => ({
  "--fluent-icon-mask": `url("${iconUrl.value}")`,
}));
</script>

<template>
  <span
    class="fluent-system-icon"
    :style="maskStyle"
    :role="label ? 'img' : undefined"
    :aria-label="label"
    :aria-hidden="label ? undefined : 'true'"
  />
</template>

<style scoped>
.fluent-system-icon {
  display: inline-block;
  width: 1em;
  height: 1em;
  flex: none;
  background-color: currentColor;
  -webkit-mask: var(--fluent-icon-mask) center / contain no-repeat;
  mask: var(--fluent-icon-mask) center / contain no-repeat;
  vertical-align: -0.125em;
}
</style>
