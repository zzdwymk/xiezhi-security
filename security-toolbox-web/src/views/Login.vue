<script setup lang="ts">
import { computed, onMounted, reactive, ref } from "vue";
import { useRoute, useRouter } from "vue-router";
import { ElMessage } from "element-plus";
import { ArrowLeft } from "../components/fluentIcons";
import { useAuthStore } from "../stores/auth";
import { toErrorMessage } from "../utils/errorMessage";

const auth = useAuthStore();
const router = useRouter();
const route = useRoute();
const desktopMode = Boolean(window.toolboxDesktop?.isDesktop);
const form = reactive({ username: auth.rememberedUsername, password: "" });
const rememberMe = ref(auth.rememberMe);
const activeAction = ref<
  "" | "password" | "credentials" | "hello" | "reset" | "init" | "generate"
>("");
const loading = computed(() => activeAction.value !== "");
const desktopLoginError = ref("");
const loginBound = ref(false);
const loginConfigured = ref(false);
const bindingLoaded = ref(false);

const quickLoginAllowed = computed(
  () =>
    !bindingLoaded.value ||
    loginBound.value ||
    !loginConfigured.value,
);

async function enterWorkspace() {
  await router.replace(String(route.query.redirect || "/"));
}

const initialCreds = ref<{ username: string; password: string } | null>(null);
const resetTitle = ref("初始账号密码");

async function generateInitialPassword() {
  const generate = window.toolboxDesktop?.generateDesktopLogin;
  if (!desktopMode || !generate || loading.value) return;
  activeAction.value = "generate";
  initMode.value = "generate";
  initialCreds.value = null;
  resetTitle.value = "初始账号密码";
  desktopLoginError.value = "";
  try {
    const result = await generate();
    initialCreds.value = {
      username: result.username,
      password: result.password,
    };
  } catch (error) {
    desktopLoginError.value = toErrorMessage(
      error,
      "生成初始密码失败，请重试",
    );
    initMode.value = "none";
  } finally {
    activeAction.value = "";
  }
}

async function resetForgottenPassword() {
  const reset = window.toolboxDesktop?.resetRandomDesktopLogin;
  if (!desktopMode || !reset || loading.value) return;
  initMode.value = "generate";
  initialCreds.value = null;
  resetTitle.value = "已重置的新密码";
  desktopLoginError.value = "";
  activeAction.value = "reset";
  try {
    const result = await reset();
    if (!result?.resettled) {
      desktopLoginError.value = result?.reason || "Windows Hello 验证未通过或被取消";
      initMode.value = "none";
      return;
    }
    initialCreds.value = {
      username: result.username || "admin",
      password: result.password || "",
    };
  } catch (error) {
    desktopLoginError.value = toErrorMessage(
      error,
      "重置登录密码失败，请重试",
    );
    initMode.value = "none";
  } finally {
    activeAction.value = "";
  }
}

function backToLogin() {
  initMode.value = "none";
  initialCreds.value = null;
  resetTitle.value = "初始账号密码";
  desktopLoginError.value = "";
}

function acceptInitialCreds() {
  if (initialCreds.value) {
    form.username = initialCreds.value.username;
    form.password = initialCreds.value.password;
  }
  backToLogin();
}
const copiedField = ref<"" | "username" | "password">("");
async function copyInitialField(field: "username" | "password") {
  const value = initialCreds.value?.[field];
  if (!value) return;
  try {
    await navigator.clipboard.writeText(value);
  } catch {
    const ta = document.createElement("textarea");
    ta.value = value;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand("copy");
    document.body.removeChild(ta);
  }
  copiedField.value = field;
  setTimeout(() => {
    if (copiedField.value === field) copiedField.value = "";
  }, 1500);
}

const initMode = ref<"none" | "generate" | "custom">("none");
const customForm = reactive({ password: "", confirm: "" });
async function initCustomPassword() {
  const init = window.toolboxDesktop?.initDesktopLogin;
  if (!desktopMode || !init || loading.value) return;
  if (customForm.password.length < 8)
    return ElMessage.warning("自定义密码至少 8 位");
  if (customForm.password !== customForm.confirm)
    return ElMessage.warning("两次输入的密码不一致");
  activeAction.value = "init";
  desktopLoginError.value = "";
  try {
    const result = await init(customForm.password);
    // 后端已用该密码重启，直接用 账号密码 登录。
    await auth.login(result.username, result.password, false);
    await enterWorkspace();
  } catch (error) {
    desktopLoginError.value = toErrorMessage(
      error,
      "自定义密码设置失败，请重试",
    );
  } finally {
    activeAction.value = "";
  }
}

async function submit() {
  if (loading.value) return;
  activeAction.value = "password";
  try {
    await auth.login(
      form.username,
      form.password,
      desktopMode ? false : rememberMe.value,
    );
    await enterWorkspace();
  } catch {
    ElMessage.error("用户名或密码错误，请确认后重试");
  } finally {
    activeAction.value = "";
  }
}

async function loginWithDesktopCredentials() {
  const getCredentials = window.toolboxDesktop?.getDesktopLoginCredentials;
  if (!desktopMode || !getCredentials || loading.value) return;
  activeAction.value = "credentials";
  desktopLoginError.value = "";
  let credentials: DesktopLoginCredentials | null | undefined;
  try {
    credentials = await getCredentials();
    if (!credentials) {
      desktopLoginError.value =
        "本次启动的本机安全登录已使用，请重新启动桌面应用后重试。";
      return;
    }
    await auth.login(credentials.username, credentials.password, false);
    await enterWorkspace();
  } catch {
    desktopLoginError.value =
      "本机安全登录未完成，请重新启动桌面应用；也可使用已有账号手动登录。";
  } finally {
    credentials = undefined;
    activeAction.value = "";
  }
}

async function loginWithWindowsHello() {
  const verify = window.toolboxDesktop?.loginWithWindowsHello;
  if (!desktopMode || !verify || loading.value) return;
  activeAction.value = "hello";
  desktopLoginError.value = "";
  try {
    const result = await verify();
    if (!result?.verified) {
      desktopLoginError.value =
        result?.available === false
          ? "本机未启用 Windows Hello（PIN／指纹／面部），请改用账号密码或本机安全凭据登录。"
          : "Windows Hello 验证未通过或被取消，请重试。";
      return;
    }
    if (!result.credentials) {
      desktopLoginError.value =
        "本次启动的本机安全登录已使用，请重启桌面应用后重试。";
      return;
    }
    await auth.login(
      result.credentials.username,
      result.credentials.password,
      false,
    );
    await enterWorkspace();
  } catch {
    desktopLoginError.value =
      "Windows Hello 登录未完成，请重试或改用其他方式登录。";
  } finally {
    activeAction.value = "";
  }
}

onMounted(async () => {
  if (!desktopMode) return;
  // 从不静默自动登录（C2）：无论是否绑定，开场都停在登录页，必须由用户主动
  // 点「本机安全凭据 / Windows Hello」或输入账号密码才能进入工作区。
  const getBinding = window.toolboxDesktop?.getDesktopLoginBinding;
  if (getBinding) {
    try {
      const binding = await getBinding();
      loginBound.value = binding?.bound === true;
      loginConfigured.value = binding?.configured === true;
    } catch {
      loginBound.value = false;
    }
  }
  bindingLoaded.value = true;
});
</script>
<template>
  <main class="login-page">
    <section class="login-card">
      <template v-if="initMode === 'none'">
      <header class="login-header">
        <div class="login-logo">
          <img src="../assets/xiezhi-mark.png" alt="" aria-hidden="true" />
        </div>
        <div>
          <h1>獬豸授权安全测试平台</h1>
          <p>Xiezhi · 本地管理端</p>
        </div>
      </header>
      <el-alert
        v-if="desktopLoginError"
        :title="desktopLoginError"
        type="warning"
        :closable="false"
        show-icon
        style="margin-bottom: 18px"
      />
      <el-form label-position="top" @keyup.enter="submit">
        <el-form-item label="用户名">
          <el-input
            v-model="form.username"
            size="default"
            autocomplete="username"
            placeholder="请输入用户名"
            :disabled="loading"
          />
        </el-form-item>
        <el-form-item label="密码">
          <el-input
            v-model="form.password"
            size="default"
            type="password"
            show-password
            autocomplete="current-password"
            placeholder="请输入密码"
            :disabled="loading"
          />
        </el-form-item>
        <div v-if="!desktopMode" class="login-options">
          <el-checkbox v-model="rememberMe">下次自动登录</el-checkbox>
        </div>
        <el-button
          type="primary"
          size="large"
          class="login-button"
          :loading="activeAction === 'password'"
          :disabled="loading || !form.username || !form.password"
          @click="submit"
          >账号密码登录</el-button
        >
        <template v-if="desktopMode">
          <template v-if="quickLoginAllowed">
            <div class="desktop-login-divider"><span>或</span></div>
            <el-button
              size="large"
              class="login-button desktop-secure-login"
              :loading="activeAction === 'credentials'"
              :disabled="loading"
              @click="loginWithDesktopCredentials"
              >使用本机安全凭据登录</el-button
            >
            <el-button
              size="large"
              class="login-button desktop-secure-login"
              :loading="activeAction === 'hello'"
              :disabled="loading"
              @click="loginWithWindowsHello"
              >使用 Windows Hello（PIN）登录</el-button
            >
          </template>
          <p
            v-else-if="bindingLoaded"
            class="desktop-login-bind-hint"
          >
            已解除本机登录绑定，快捷登录已关闭，请使用账号密码登录。
          </p>
          <p
            v-if="bindingLoaded && !loginConfigured"
            class="desktop-login-bind-hint"
          >
            首次无需输入密码：点上面「本机安全凭据」或「Windows Hello」即可进入；之后在「设置 →
            修改登录密码」设置并绑定账号密码后，才能用账号密码登录。
          </p>
          <div
            v-if="bindingLoaded && !loginConfigured"
            class="desktop-login-firstrun"
          >
            <div class="desktop-login-firstrun-opts">
              <el-button
                link
                type="primary"
                :disabled="loading"
                @click="generateInitialPassword"
                >使用随机生成密码</el-button
              >
              <span class="desktop-login-firstrun-sep">或</span>
              <el-button
                link
                type="primary"
                :disabled="loading"
                @click="initMode = 'custom'"
                >自定义我自己的密码</el-button
              >
            </div>
          </div>
          <div
            v-if="bindingLoaded && loginConfigured"
            class="desktop-login-forgot"
          >
            <el-button link type="primary" :disabled="loading" @click="resetForgottenPassword"
              >忘记了密码？本机验证后重置</el-button
            >
          </div>
        </template>
      </el-form>
      <footer class="login-footer">
        <span>{{
          desktopMode ? "" : "环境检查已完成"
        }}</span
        ><el-button link type="primary" @click="$router.push('/setup')"
          >重新检测</el-button
        >
      </footer>
      </template>

      <template v-else>
        <button type="button" class="login-back" @click="backToLogin">
          <el-icon><ArrowLeft /></el-icon><span>返回登录</span>
        </button>

        <template v-if="initMode === 'generate'">
          <h2 class="login-subtitle">{{ resetTitle }}</h2>
          <p class="initial-creds-note" v-if="resetTitle === '已重置的新密码'">
            你的登录密码已被重置为下方的新随机强密码（仅本次显示，请立即保存；也可在进入后到 设置把密码改成自己记得的）。
          </p>
          <p class="initial-creds-note" v-else>
            这是你的初始登录账号密码（仅本次显示，请立即保存到安全位置；之后可在 设置 →
            修改登录密码 中更改并绑定）。
          </p>
          <div v-if="initialCreds" class="initial-creds">
            <div
              class="initial-creds-field"
              role="button"
              tabindex="0"
              @click="copyInitialField('username')"
              @keyup.enter="copyInitialField('username')"
            >
              <span class="initial-creds-label">用户名</span>
              <code class="initial-creds-value">{{ initialCreds.username }}</code>
              <span
                v-if="copiedField === 'username'"
                class="initial-creds-ok"
                >已复制</span
              >
              <span v-else class="initial-creds-copy-hint">点击复制</span>
            </div>
            <div
              class="initial-creds-field"
              role="button"
              tabindex="0"
              @click="copyInitialField('password')"
              @keyup.enter="copyInitialField('password')"
            >
              <span class="initial-creds-label">密码</span>
              <code class="initial-creds-value">{{ initialCreds.password }}</code>
              <span
                v-if="copiedField === 'password'"
                class="initial-creds-ok"
                >已复制</span
              >
              <span v-else class="initial-creds-copy-hint">点击复制</span>
            </div>
          </div>
          <p v-else class="login-sub-empty">正在生成初始账号密码…</p>
          <el-button
            type="primary"
            size="large"
            class="login-button initial-creds-submit"
            :disabled="!initialCreds"
            @click="acceptInitialCreds"
            >我已保存，返回登录</el-button
          >
        </template>

        <template v-else>
          <h2 class="login-subtitle">自定义登录密码</h2>
          <el-alert
            v-if="desktopLoginError"
            :title="desktopLoginError"
            type="warning"
            :closable="false"
            show-icon
            style="margin-bottom: 14px"
          />
          <el-form label-position="top" @keyup.enter="initCustomPassword">
            <el-form-item label="新密码（至少 8 位）">
              <el-input
                v-model="customForm.password"
                type="password"
                show-password
                autocomplete="new-password"
                placeholder="设置你要的登录密码"
                :disabled="loading"
              />
            </el-form-item>
            <el-form-item label="确认新密码">
              <el-input
                v-model="customForm.confirm"
                type="password"
                show-password
                autocomplete="new-password"
                placeholder="再次输入新密码"
                :disabled="loading"
              />
            </el-form-item>
            <p class="desktop-login-custom-note">
              保存后即绑定到本机凭据与 Windows Hello，此后可用本机/Hello 快捷登录。
            </p>
            <el-button
              type="primary"
              size="large"
              class="login-button"
              :loading="activeAction === 'init'"
              :disabled="
                loading ||
                customForm.password.length < 8 ||
                customForm.password !== customForm.confirm
              "
              @click="initCustomPassword"
              >使用该密码并进入</el-button
            >
          </el-form>
        </template>
      </template>
    </section>
  </main>
</template>

<style scoped>
.desktop-login-divider {
  display: flex;
  align-items: center;
  gap: 12px;
  margin: 16px 0 12px;
  color: var(--app-muted);
  font-size: 12px;
}
.desktop-login-divider::before,
.desktop-login-divider::after {
  height: 1px;
  flex: 1;
  background: var(--app-border);
  content: "";
}
.desktop-secure-login {
  color: var(--app-text);
  border-color: var(--app-border-strong);
  background: var(--app-surface-soft);
}
.desktop-secure-login:hover:not(.is-disabled):not(:disabled),
.desktop-secure-login:focus-visible:not(.is-disabled):not(:disabled) {
  color: var(--app-accent-strong);
  border-color: var(--app-accent);
  background: var(--app-accent-soft);
}
.desktop-secure-login.is-disabled,
.desktop-secure-login:disabled {
  color: var(--fluent-disabled-fg) !important;
  border-color: var(--fluent-disabled-border) !important;
  background: var(--fluent-disabled-bg) !important;
}
.desktop-login-bind-hint {
  margin: 10px 0 0;
  color: var(--app-muted);
  font-size: 12px;
  line-height: 1.6;
}
.desktop-login-forgot {
  display: flex;
  justify-content: center;
  margin-top: 12px;
}
.desktop-login-forgot :deep(.el-button.is-link),
.desktop-login-firstrun :deep(.el-button.is-link) {
  background: transparent !important;
  border-color: transparent !important;
  box-shadow: none !important;
}
.desktop-login-firstrun {
  display: flex;
  flex-direction: column;
  align-items: stretch;
  gap: 10px;
  margin-top: 10px;
  text-align: center;
}
.desktop-login-firstrun-opts {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
}
.desktop-login-firstrun-sep {
  color: var(--app-muted);
  font-size: 12px;
}
.desktop-login-custom-note {
  margin: 4px 0 14px;
  color: var(--app-muted);
  font-size: 12px;
  line-height: 1.6;
}
.login-back {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  margin: 0 0 14px;
  padding: 4px 8px 4px 4px;
  border: 0;
  border-radius: 6px;
  background: transparent;
  color: var(--app-accent);
  font: inherit;
  font-size: 13px;
  font-weight: 600;
  cursor: pointer;
}
.login-back:hover {
  color: var(--app-accent-strong);
}
.login-subtitle {
  margin: 0 0 12px;
  color: var(--app-text);
  font-size: 17px;
  font-weight: 650;
}
.login-sub-empty {
  margin: 0 0 16px;
  padding: 18px 0;
  color: var(--app-muted);
  font-size: 13px;
  text-align: center;
}
.initial-creds-submit {
  margin-top: 16px !important;
}
.initial-creds-note {
  margin: 0 0 14px;
  color: var(--app-muted);
  font-size: 12px;
  line-height: 1.6;
}
.initial-creds {
  display: flex;
  flex-direction: column;
  overflow: hidden;
  border: 1px solid var(--app-border);
  border-radius: 8px;
  background: var(--app-surface-soft);
}
.initial-creds-field {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 6px 8px 6px 14px;
  cursor: pointer;
}
.initial-creds-field + .initial-creds-field {
  border-top: 1px solid var(--app-border);
}
.initial-creds-field:hover {
  background: var(--app-accent-soft);
}
.initial-creds-label {
  flex: none;
  width: 42px;
  color: var(--app-muted);
  font-size: 12px;
}
.initial-creds-value {
  min-width: 0;
  flex: 1;
  color: var(--app-text);
  font: 13px/1.6 Consolas, "Microsoft YaHei", monospace;
  overflow-wrap: anywhere;
  user-select: all;
}
.initial-creds-copy-hint,
.initial-creds-ok {
  flex: none;
  font-size: 12px;
}
.initial-creds-copy-hint {
  color: var(--app-muted);
}
.initial-creds-ok {
  color: var(--app-accent);
  font-weight: 600;
}
/* Input edges/focus come from the shared Fluent control layer so login
   matches the main workspace 1:1 — no page-local box-shadow overrides. */

/* Match main-shell Fluent TextBox: soft rest edge + bottom accent on focus. */
.login-card :deep(.el-input__wrapper),
.login-card :deep(.el-select__wrapper) {
  min-height: var(--fluent-control-height) !important;
  border: 0 !important;
  border-radius: var(--fluent-radius-control) !important;
  background: var(--app-surface-strong) !important;
  box-shadow: 0 0 0 var(--fluent-stroke-thin) var(--app-border) inset !important;
  transition:
    box-shadow var(--fluent-fast),
    background-color var(--fluent-fast);
}
.login-card :deep(.el-input__wrapper:hover),
.login-card :deep(.el-select__wrapper:hover) {
  box-shadow: 0 0 0 var(--fluent-stroke-thin) var(--app-border) inset !important;
}
.login-card :deep(.el-input__wrapper.is-focus),
.login-card :deep(.el-select__wrapper.is-focused) {
  /* Keep neutral frame; only the bottom edge turns into the Fluent accent bar. */
  box-shadow:
    inset 0 0 0 1px var(--app-border),
    inset 0 -2px 0 0 var(--app-accent) !important;
}
.login-card :deep(.el-input__inner),
.login-card :deep(.el-input__inner:focus),
.login-card :deep(.el-input__inner:focus-visible) {
  outline: none !important;
  box-shadow: none !important;
  color: var(--app-text);
}
.login-card :deep(.el-form-item__label) {
  color: var(--app-text) !important;
  font-weight: 600;
}
</style>
