import { defineStore } from "pinia";
import { api } from "../api";
import {
  clearAuthToken,
  hasPersistentAuthToken,
  readAuthToken,
  storeAuthToken,
} from "../authToken";

interface UserInfo {
  id?: number;
  username: string;
  role: string;
}

interface LoginResponse {
  token: string;
  tokenType: string;
  expiresIn: number;
  user: UserInfo;
}

const REMEMBER_KEY = "security_toolbox_remember_login";
const USERNAME_KEY = "security_toolbox_login_username";

function readRememberPreference() {
  const saved = localStorage.getItem(REMEMBER_KEY);
  // Existing installations persisted the token before the preference existed;
  // treat that token as an opted-in remembered session for backwards compatibility.
  return saved === null ? hasPersistentAuthToken() : saved === "true";
}

export const useAuthStore = defineStore("auth", {
  state: () => ({
    token: readAuthToken(),
    user: null as UserInfo | null,
    checked: false,
    rememberMe: readRememberPreference(),
    rememberedUsername: localStorage.getItem(USERNAME_KEY) || "",
  }),
  getters: {
    isAuthenticated: (state) => Boolean(state.token),
  },
  actions: {
    async login(username: string, password: string, rememberMe?: boolean) {
      const { data } = await api.post<LoginResponse>("/auth/login", {
        username,
        password,
      });
      const shouldRemember = rememberMe ?? this.rememberMe;
      this.token = data.token;
      this.user = data.user;
      this.checked = true;
      this.rememberMe = shouldRemember;
      localStorage.setItem(REMEMBER_KEY, String(shouldRemember));
      storeAuthToken(data.token, shouldRemember);
      if (shouldRemember) {
        localStorage.setItem(USERNAME_KEY, username);
        this.rememberedUsername = username;
      } else {
        localStorage.removeItem(USERNAME_KEY);
        this.rememberedUsername = "";
      }
    },
    async fetchMe() {
      if (!this.token) {
        this.checked = true;
        return false;
      }
      try {
        const { data } = await api.get<UserInfo>("/auth/me");
        this.user = data;
        return true;
      } catch {
        this.clear();
        return false;
      } finally {
        this.checked = true;
      }
    },
    clear() {
      this.token = "";
      this.user = null;
      this.checked = true;
      clearAuthToken();
    },
    logout() {
      this.clear();
    },
  },
});
