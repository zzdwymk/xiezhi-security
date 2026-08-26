import { createApp } from "vue";
import { createPinia } from "pinia";
import { ElTable } from "element-plus";
import "element-plus/es/components/message/style/css";
import "element-plus/es/components/message-box/style/css";
import "./desktop-v2.css";
import "./unified-theme.css";
import "./fluent-design-2.css";
import "./fluent-design-3.css";
import { initializeSystemTheme } from "./system-theme";
import App from "./App.vue";
import router from "./router";

const tableComponent = ElTable as any;
if (tableComponent?.props?.border !== undefined) {
  tableComponent.props.border = {
    type: Boolean,
    default: true,
  };
}

async function bootstrap() {
  await initializeSystemTheme();
  createApp(App)
    .use(createPinia())
    .use(router)
    .mount("#app");
}

void bootstrap();
