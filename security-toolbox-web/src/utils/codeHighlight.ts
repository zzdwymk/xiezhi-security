/**
 * Code formatting, syntax highlighting and interactive copy enhancement for Markdown code blocks.
 */

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

export function normalizeLanguage(lang?: string): string {
  if (!lang) return "";
  const cleaned = lang.trim().toLowerCase().replace(/^language-/, "");
  const map: Record<string, string> = {
    js: "javascript",
    ts: "typescript",
    py: "python",
    sh: "bash",
    shell: "bash",
    zsh: "bash",
    yml: "yaml",
  };
  return map[cleaned] || cleaned;
}

export function detectLanguage(code: string, explicitLang?: string): string {
  const norm = normalizeLanguage(explicitLang);
  if (norm) return norm;

  const trimmed = code.trim();
  if (
    (trimmed.startsWith("{") && trimmed.endsWith("}")) ||
    (trimmed.startsWith("[") && trimmed.endsWith("]"))
  ) {
    try {
      JSON.parse(trimmed);
      return "json";
    } catch {}
  }
  if (
    /^(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+\S+\s+HTTP\/\d/i.test(trimmed) ||
    /^HTTP\/\d\.\d\s+\d{3}/i.test(trimmed)
  ) {
    return "http";
  }
  if (/^(?:SELECT|INSERT|UPDATE|DELETE|CREATE|ALTER|DROP|USE)\s+/i.test(trimmed)) {
    return "sql";
  }
  if (
    /^(?:curl|nmap|sqlmap|fscan|nuclei|bash|python|npm|pnpm|git)\s+/i.test(trimmed) ||
    /^#!\/(?:bin|usr)/.test(trimmed)
  ) {
    return "bash";
  }
  return "text";
}

export function formatCode(code: string, lang: string): string {
  if (lang === "json") {
    try {
      const trimmed = code.trim();
      const parsed = JSON.parse(trimmed);
      if (typeof parsed === "object" && parsed !== null && Object.keys(parsed).length === 0) {
        return Array.isArray(parsed) ? "[]" : "{}";
      }
      return JSON.stringify(parsed, null, 2);
    } catch {
      return code;
    }
  }
  return code;
}

export function highlightCode(code: string, lang: string): string {
  const normalized = normalizeLanguage(lang);
  switch (normalized) {
    case "json":
      return highlightJson(code);
    case "javascript":
    case "typescript":
      return highlightJs(code);
    case "python":
      return highlightPython(code);
    case "bash":
      return highlightBash(code);
    case "sql":
      return highlightSql(code);
    case "http":
      return highlightHttp(code);
    default:
      return escapeHtml(code);
  }
}

export function getLanguageLabel(lang: string): string {
  const labels: Record<string, string> = {
    json: "JSON",
    javascript: "JavaScript",
    typescript: "TypeScript",
    python: "Python",
    bash: "Bash",
    sql: "SQL",
    http: "HTTP",
    html: "HTML",
    xml: "XML",
    yaml: "YAML",
    text: "TEXT",
  };
  return labels[lang.toLowerCase()] || lang.toUpperCase() || "CODE";
}

function highlightJson(code: string): string {
  const escaped = escapeHtml(code);
  return escaped.replace(
    /(&quot;(?:\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\&])*&quot;(\s*:)?|\b(?:true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?|[{}[\],:])/g,
    (match) => {
      if (match.startsWith("&quot;")) {
        if (match.endsWith(":")) {
          const key = match.slice(0, -1).trim();
          return `<span class="token-key">${key}</span>:`;
        }
        return `<span class="token-string">${match}</span>`;
      }
      if (match === "true" || match === "false") {
        return `<span class="token-boolean">${match}</span>`;
      }
      if (match === "null") {
        return `<span class="token-null">${match}</span>`;
      }
      if (/^-?\d/.test(match)) {
        return `<span class="token-number">${match}</span>`;
      }
      if (/[{}[\],:]/.test(match)) {
        return `<span class="token-punctuation">${match}</span>`;
      }
      return match;
    },
  );
}

function highlightJs(code: string): string {
  const escaped = escapeHtml(code);
  return escaped.replace(
    /(\/\/[^\n]*|\/\*[\s\S]*?\*\/|&quot;(?:\\.|[^&"\\])*&quot;|&#039;(?:\\.|[^&#039;\\])*&#039;|`(?:\\.|[^`\\])*`|\b(?:const|let|var|function|return|if|else|import|export|from|as|async|await|class|try|catch|finally|throw|new|this|typeof|instanceof|while|for|of|in|switch|case|default|break|continue)\b|\b(?:true|false|null|undefined)\b|-?\b\d+(?:\.\d+)?\b)/g,
    (match) => {
      if (match.startsWith("//") || match.startsWith("/*")) {
        return `<span class="token-comment">${match}</span>`;
      }
      if (match.startsWith("&quot;") || match.startsWith("&#039;") || match.startsWith("`")) {
        return `<span class="token-string">${match}</span>`;
      }
      if (match === "true" || match === "false") {
        return `<span class="token-boolean">${match}</span>`;
      }
      if (match === "null" || match === "undefined") {
        return `<span class="token-null">${match}</span>`;
      }
      if (/^-?\d/.test(match)) {
        return `<span class="token-number">${match}</span>`;
      }
      return `<span class="token-keyword">${match}</span>`;
    },
  );
}

function highlightPython(code: string): string {
  const escaped = escapeHtml(code);
  return escaped.replace(
    /(#[^\n]*|&quot;&quot;&quot;[\s\S]*?&quot;&quot;&quot;|&#039;&#039;&#039;[\s\S]*?&#039;&#039;&#039;|&quot;(?:\\.|[^&"\\])*&quot;|&#039;(?:\\.|[^&#039;\\])*&#039;|\b(?:def|class|import|from|return|if|elif|else|try|except|finally|raise|for|while|with|as|in|is|not|and|or|pass|break|continue|lambda|yield|global|nonlocal)\b|\b(?:True|False|None)\b|-?\b\d+(?:\.\d+)?\b)/g,
    (match) => {
      if (match.startsWith("#")) {
        return `<span class="token-comment">${match}</span>`;
      }
      if (match.startsWith("&quot;") || match.startsWith("&#039;")) {
        return `<span class="token-string">${match}</span>`;
      }
      if (match === "True" || match === "False") {
        return `<span class="token-boolean">${match}</span>`;
      }
      if (match === "None") {
        return `<span class="token-null">${match}</span>`;
      }
      if (/^-?\d/.test(match)) {
        return `<span class="token-number">${match}</span>`;
      }
      return `<span class="token-keyword">${match}</span>`;
    },
  );
}

function highlightBash(code: string): string {
  const escaped = escapeHtml(code);
  return escaped.replace(
    /(#[^\n]*|&quot;(?:\\.|[^&"\\])*&quot;|&#039;(?:\\.|[^&#039;\\])*&#039;|\$[A-Za-z0-9_]+|\$\{[A-Za-z0-9_]+\}|--?[a-zA-Z0-9_-]+|\b(?:curl|nmap|sqlmap|fscan|nuclei|bash|python|sudo|echo|grep|cat|chmod|export|if|then|else|elif|fi|for|do|done|while|case|esac)\b)/g,
    (match) => {
      if (match.startsWith("#")) {
        return `<span class="token-comment">${match}</span>`;
      }
      if (match.startsWith("&quot;") || match.startsWith("&#039;")) {
        return `<span class="token-string">${match}</span>`;
      }
      if (match.startsWith("$")) {
        return `<span class="token-variable">${match}</span>`;
      }
      if (match.startsWith("-")) {
        return `<span class="token-operator">${match}</span>`;
      }
      return `<span class="token-keyword">${match}</span>`;
    },
  );
}

function highlightSql(code: string): string {
  const escaped = escapeHtml(code);
  return escaped.replace(
    /(--[^\n]*|\/\*[\s\S]*?\*\/|&#039;(?:\\.|[^&#039;\\])*&#039;|&quot;(?:\\.|[^&"\\])*&quot;|\b(?:SELECT|FROM|WHERE|INSERT|INTO|VALUES|UPDATE|SET|DELETE|CREATE|TABLE|ALTER|DROP|JOIN|LEFT|RIGHT|INNER|OUTER|ON|GROUP\s+BY|ORDER\s+BY|HAVING|LIMIT|UNION|ALL|AND|OR|NOT|IN|EXISTS|BETWEEN|LIKE|IS|NULL|AS|DISTINCT|CASE|WHEN|THEN|ELSE|END)\b|-?\b\d+(?:\.\d+)?\b)/gi,
    (match) => {
      if (match.startsWith("--") || match.startsWith("/*")) {
        return `<span class="token-comment">${match}</span>`;
      }
      if (match.startsWith("&#039;") || match.startsWith("&quot;")) {
        return `<span class="token-string">${match}</span>`;
      }
      if (/^-?\d/.test(match)) {
        return `<span class="token-number">${match}</span>`;
      }
      return `<span class="token-keyword">${match.toUpperCase()}</span>`;
    },
  );
}

function highlightHttp(code: string): string {
  const escaped = escapeHtml(code);
  return escaped.replace(
    /^((?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+\S+\s+HTTP\/\d\.\d|HTTP\/\d\.\d\s+\d{3}[^\n]*)|^([A-Za-z0-9_-]+:)/gm,
    (match, statusLine, headerName) => {
      if (statusLine) {
        return `<span class="token-keyword">${statusLine}</span>`;
      }
      if (headerName) {
        return `<span class="token-key">${headerName}</span>`;
      }
      return match;
    },
  );
}

export function initializeMarkdownCopyListener() {
  if (typeof document === "undefined") return;
  const w = window as any;
  if (w.__markdownCopyListenerInstalled) return;
  w.__markdownCopyListenerInstalled = true;

  document.addEventListener("click", async (event) => {
    const target = event.target as HTMLElement | null;
    const button = target?.closest(".code-copy-btn") as HTMLButtonElement | null;
    if (!button) return;

    const wrapper = button.closest(".code-block-wrapper");
    const codeEl = wrapper?.querySelector("code") || wrapper?.querySelector("pre");
    const textToCopy = (codeEl?.textContent ?? "").replace(/\r\n/g, "\n");
    if (!textToCopy) return;

    let success = false;
    try {
      if (navigator?.clipboard?.writeText) {
        await navigator.clipboard.writeText(textToCopy);
        success = true;
      }
    } catch {}

    if (!success) {
      try {
        const textarea = document.createElement("textarea");
        textarea.value = textToCopy;
        textarea.style.position = "fixed";
        textarea.style.opacity = "0";
        document.body.appendChild(textarea);
        textarea.select();
        success = document.execCommand("copy");
        document.body.removeChild(textarea);
      } catch {}
    }

    button.classList.add("is-copied");
    const textSpan = button.querySelector(".code-copy-text");
    if (textSpan) textSpan.textContent = "已复制";

    setTimeout(() => {
      button.classList.remove("is-copied");
      if (textSpan) textSpan.textContent = "复制";
    }, 2000);
  });
}
