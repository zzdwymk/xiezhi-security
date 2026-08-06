<script setup lang="ts">
import { onMounted, reactive, ref } from "vue";
import { useRoute, useRouter } from "vue-router";
import { ElMessage } from "element-plus";
import { useAuthStore } from "../stores/auth";

const auth = useAuthStore();
const router = useRouter();
const route = useRoute();
const desktopMode = Boolean(window.toolboxDesktop?.isDesktop);
const form = reactive({ username: auth.rememberedUsername, password: "" });
const rememberMe = ref(auth.rememberMe);
const loading = ref(false);
const desktopLoginError = ref("");

async function enterWorkspace() {
  await router.replace(String(route.query.redirect || "/"));
}

async function submit() {
  if (loading.value) return;
  loading.value = true;
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
    loading.value = false;
  }
}

async function loginWithDesktopCredentials() {
  const getCredentials = window.toolboxDesktop?.getDesktopLoginCredentials;
  if (!desktopMode || !getCredentials || loading.value) return;
  loading.value = true;
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
    loading.value = false;
  }
}

async function loginWithWindowsHello() {
  const verify = window.toolboxDesktop?.loginWithWindowsHello;
  if (!desktopMode || !verify || loading.value) return;
  loading.value = true;
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
    loading.value = false;
  }
}

onMounted(async () => {
  if (!desktopMode) return;
  // Auto-login only on the first login screen per launch, so after logging out the user can
  // freely choose 本机安全凭据 / Windows Hello / 账号密码 instead of being signed straight back in.
  if (sessionStorage.getItem("secbox_autologin_done")) return;
  sessionStorage.setItem("secbox_autologin_done", "1");
  const getCredentials = window.toolboxDesktop?.getDesktopLoginCredentials;
  if (!getCredentials || loading.value) return;
  loading.value = true;
  try {
    const credentials = await getCredentials();
    if (credentials) {
      await auth.login(credentials.username, credentials.password, false);
      await enterWorkspace();
      return;
    }
  } catch {
    /* fall back to the manual login form */
  } finally {
    loading.value = false;
  }
});
</script>
<template>
  <main class="login-page">
    <section class="login-card">
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
          :loading="loading"
          :disabled="loading || !form.username || !form.password"
          @click="submit"
          >账号密码登录</el-button
        >
        <template v-if="desktopMode">
          <div class="desktop-login-divider"><span>或</span></div>
          <el-button
            size="large"
            class="login-button desktop-secure-login"
            :loading="loading"
            :disabled="loading"
            @click="loginWithDesktopCredentials"
            >使用本机安全凭据登录</el-button
          >
          <el-button
            size="large"
            class="login-button desktop-secure-login"
            :loading="loading"
            :disabled="loading"
            @click="loginWithWindowsHello"
            >使用 Windows Hello（PIN）登录</el-button
          >
        </template>
      </el-form>
      <footer class="login-footer">
        <span>{{
          desktopMode ? "每次启动均需显式登录" : "环境检查已完成"
        }}</span
        ><el-button link type="primary" @click="$router.push('/setup')"
          >重新检测</el-button
        >
      </footer>
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
.desktop-secure-login:hover,
.desktop-secure-login:focus-visible {
  color: var(--app-accent-strong);
  border-color: var(--app-accent);
  background: var(--app-accent-soft);
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
