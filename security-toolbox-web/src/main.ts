import { createApp } from "vue";
import { createPinia } from "pinia";
import ElementPlus from "element-plus";
import zhCn from "element-plus/es/locale/lang/zh-cn";
import "element-plus/dist/index.css";
import "./plans.css";
import "./setup.css";
import "./desktop-v2.css";
import "./offline-tools.css";
import "./network-offline-tools.css";
import "./unified-theme.css";
import "./fluent-design-2.css";
import { initializeSystemTheme } from "./system-theme";
import App from "./App.vue";
import router from "./router";

async function bootstrap() {
  await initializeSystemTheme();
  createApp(App)
    .use(createPinia())
    .use(router)
    .use(ElementPlus, { locale: zhCn })
    .mount("#app");
}

void bootstrap();
