import { defineComponent, h, type Component } from "vue";
import FluentIcon from "./FluentIcon.vue";

function fluentIcon(name: string): Component {
  return defineComponent({
    name: `Fluent${name}`,
    inheritAttrs: false,
    setup(_, { attrs }) {
      return () => h(FluentIcon, { ...attrs, name });
    },
  });
}

export const Aim = fluentIcon("target");
export const ArrowDown = fluentIcon("chevron-down");
export const ArrowRight = fluentIcon("chevron-right");
export const ArrowUp = fluentIcon("chevron-up");
export const ChatDotRound = fluentIcon("chat");
export const Check = fluentIcon("checkmark");
export const CircleCheck = fluentIcon("checkmark-circle");
export const Clock = fluentIcon("clock");
export const Coin = fluentIcon("hash");
export const Compass = fluentIcon("globe-search");
export const Connection = fluentIcon("arrow-bidirectional");
export const CopyDocument = fluentIcon("copy");
export const DataAnalysis = fluentIcon("data");
export const Delete = fluentIcon("delete");
export const Document = fluentIcon("document");
export const DocumentChecked = fluentIcon("document-checkmark");
export const Dismiss = fluentIcon("dismiss");
export const Download = fluentIcon("arrow-download");
export const EditPen = fluentIcon("edit");
export const Expand = fluentIcon("chevron-down");
export const Files = fluentIcon("document-multiple");
export const Filter = fluentIcon("filter");
export const Flag = fluentIcon("flag");
export const Fold = fluentIcon("chevron-up");
export const FolderOpened = fluentIcon("folder-open");
export const HomeFilled = fluentIcon("home");
export const Key = fluentIcon("key");
export const List = fluentIcon("clipboard-task");
export const Location = fluentIcon("location");
export const Lock = fluentIcon("lock");
export const MagicStick = fluentIcon("sparkle");
export const Plus = fluentIcon("add");
export const Promotion = fluentIcon("send");
export const QuestionFilled = fluentIcon("question");
export const Refresh = fluentIcon("arrow-clockwise");
export const RefreshLeft = fluentIcon("arrow-reset");
export const Search = fluentIcon("search");
export const Setting = fluentIcon("settings");
export const Share = fluentIcon("branch-fork");
export const Star = fluentIcon("star");
export const StarFilled = fluentIcon("star-filled");
export const Switch = fluentIcon("arrow-swap");
export const SwitchButton = fluentIcon("sign-out");
export const Tickets = fluentIcon("clipboard-text");
export const Tools = fluentIcon("wrench");
export const UploadFilled = fluentIcon("arrow-upload");
export const VideoPause = fluentIcon("pause");
export const VideoPlay = fluentIcon("play");
export const View = fluentIcon("eye");
export const Warning = fluentIcon("warning");
