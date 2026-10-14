import DOMPurify from "dompurify";
import { Marked, Tokenizer } from "marked";
import { localizeAiDisplayText, localizeAiInlineIdentifier, type AiDisplayTextOptions } from "./aiPresentation";
import { detectLanguage, formatCode, highlightCode, getLanguageLabel } from "./codeHighlight";

const cache = new Map<string, string>();
const MAX_CACHE_ENTRIES = 200;

const markdown = new Marked({
  gfm: true,
  breaks: true,
  tokenizer: {
    url(source) {
      const token = Tokenizer.prototype.url.call(this, source);
      if (!token || !/^(?:https?:\/\/|www\.)/i.test(token.raw)) return token;
      // GFM accepts adjacent Chinese prose as part of a bare URL. Consume only
      // its ASCII address so the lexer can render the remaining prose normally.
      // Explicit [label](url), <url>, code, and percent-encoded URLs are untouched.
      const boundary = token.raw.search(/[^\x21-\x7e]/);
      if (boundary < 0) return token;
      const prefix = token.raw.slice(0, boundary);
      try {
        const address = new URL(/^www\./i.test(prefix) ? `http://${prefix}` : prefix);
        if (!address.hostname) return token;
      } catch {
        // An internationalized hostname cannot be inferred from an ASCII prefix.
        return token;
      }
      return Tokenizer.prototype.url.call(this, prefix) || token;
    },
  },
});

export function renderMarkdown(value: string, options: AiDisplayTextOptions & {
  localizeToolCodes?: boolean;
  localizeDisplayText?: boolean;
} = {}) {
  const source = value || "";
  const localize = options.localizeDisplayText ?? options.localizeToolCodes ?? false;
  const cacheKey = `${localize ? JSON.stringify([options.nodeLabels || {}, options.termLabels || {}]) : "raw"}\0${source}`;
  const cached = cache.get(cacheKey);
  if (cached !== undefined) return cached;

  const raw = markdown.parse(source) as string;
  const sanitized = DOMPurify.sanitize(raw, {
    USE_PROFILES: { html: true },
    FORBID_TAGS: [
      "style",
      "iframe",
      "object",
      "embed",
      "form",
      "input",
      "button",
      "img",
      "picture",
      "source",
      "video",
      "audio",
      "track",
    ],
    FORBID_ATTR: ["style", "srcdoc"],
  });
  const template = document.createElement("template");
  template.innerHTML = sanitized;
  template.content.querySelectorAll("a").forEach((anchor) => {
    const href = anchor.getAttribute("href") || "";
    if (/^https?:\/\//i.test(href)) {
      anchor.target = "_blank";
      anchor.rel = "noopener noreferrer";
    } else if (!href.startsWith("#")) {
      anchor.removeAttribute("href");
    }
  });
  if (localize) {
    template.content.querySelectorAll("[title]").forEach((element) => {
      element.setAttribute("title", localizeAiDisplayText(element.getAttribute("title") || "", options));
    });
    const walker = document.createTreeWalker(template.content, NodeFilter.SHOW_TEXT);
    let node: Node | null;
    while ((node = walker.nextNode())) {
      const parent = node.parentElement;
      if (parent?.closest("pre, kbd, samp")) continue;
      // The displayed URL and its destination stay byte-for-byte intact. A prose link label
      // may be localized, but auto-linked URLs and addresses in labels remain protected.
      const code = parent?.closest("code");
      if (code) {
        if (code.childNodes.length === 1)
          node.textContent = localizeAiInlineIdentifier(node.textContent || "", options);
      } else {
        node.textContent = localizeAiDisplayText(node.textContent || "", options);
      }
    }
  }
  template.content.querySelectorAll("pre").forEach((pre) => {
    if (pre.parentElement?.classList.contains("code-block-wrapper")) return;

    const codeEl = pre.querySelector("code");
    const rawCode = (codeEl ? codeEl.textContent : pre.textContent) || "";

    const langClass = Array.from(codeEl?.classList || []).find((c) => c.startsWith("language-"));
    const explicitLang = langClass ? langClass.replace(/^language-/, "") : "";
    const detectedLang = detectLanguage(rawCode, explicitLang);
    const langLabel = getLanguageLabel(detectedLang);

    const formattedCode = formatCode(rawCode, detectedLang);
    const highlightedHtml = highlightCode(formattedCode, detectedLang);

    const wrapper = document.createElement("div");
    wrapper.className = `code-block-wrapper code-lang-${detectedLang}`;
    wrapper.setAttribute("data-lang", detectedLang);

    const header = document.createElement("div");
    header.className = "code-block-header";
    header.setAttribute("data-code-header", "true");

    const badge = document.createElement("span");
    badge.className = "code-block-badge";
    badge.textContent = langLabel;
    header.appendChild(badge);

    const copyBtn = document.createElement("button");
    copyBtn.type = "button";
    copyBtn.className = "code-copy-btn";
    copyBtn.setAttribute("aria-label", "复制代码");
    copyBtn.innerHTML = `
      <svg class="code-copy-icon" viewBox="0 0 16 16" width="13" height="13" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
        <rect x="5.5" y="5.5" width="8" height="8" rx="1.5"></rect>
        <path d="M3.5 10.5V3.5A1.5 1.5 0 0 1 5 2h5.5"></path>
      </svg>
      <svg class="code-copy-check" viewBox="0 0 16 16" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
        <path d="M3.5 8.5L6.5 11.5L12.5 4.5"></path>
      </svg>
      <span class="code-copy-text">复制</span>
    `;
    header.appendChild(copyBtn);

    if (codeEl) {
      codeEl.className = `language-${detectedLang}`;
      codeEl.innerHTML = highlightedHtml;
    } else {
      pre.innerHTML = `<code class="language-${detectedLang}">${highlightedHtml}</code>`;
    }

    pre.parentNode?.insertBefore(wrapper, pre);
    wrapper.appendChild(header);
    wrapper.appendChild(pre);
  });
  const html = template.innerHTML;
  cache.set(cacheKey, html);
  if (cache.size > MAX_CACHE_ENTRIES)
    cache.delete(cache.keys().next().value as string);
  return html;
}

/** Copy readable text while retaining paragraph, list, table, and code boundaries. */
export function markdownToPlainText(value: string) {
  const template = document.createElement("template");
  template.innerHTML = renderMarkdown(value);
  const blockTags = new Set(["P", "DIV", "SECTION", "ARTICLE", "H1", "H2", "H3", "H4", "H5", "H6", "BLOCKQUOTE", "PRE", "UL", "OL", "TABLE", "HR"]);

  function childrenText(node: Node): string {
    let result = "";
    let previousBlock = false;
    for (const child of node.childNodes) {
      if (child instanceof Element && child.classList.contains("code-block-header")) continue;
      const block = child instanceof Element && blockTags.has(child.tagName);
      const text = nodeText(child);
      if (!text || (!text.trim() && (!result || previousBlock))) continue;
      if (result && (block || previousBlock)) result = (previousBlock ? result : result.trimEnd()) + "\n\n";
      result += text;
      previousBlock = block;
    }
    return result;
  }

  function nodeText(node: Node): string {
    if (node.nodeType === Node.TEXT_NODE) return (node.textContent || "").replace(/\s+/g, " ");
    if (!(node instanceof Element)) return "";
    if (node.tagName === "BR") return "\n";
    if (node.tagName === "PRE") return (node.textContent || "").replace(/\n$/, "");
    if (node.tagName === "CODE") return node.textContent || "";
    if (node.tagName === "UL" || node.tagName === "OL") {
      const start = Number(node.getAttribute("start")) || 1;
      return Array.from(node.children).map((item, index) => {
        const prefix = node.tagName === "OL" ? `${start + index}. ` : "• ";
        return prefix + childrenText(item).trim().replace(/\n/g, "\n  ");
      }).join("\n");
    }
    if (node.tagName === "TABLE") {
      return Array.from(node.querySelectorAll("tr")).map(row =>
        Array.from(row.children).map(cell => childrenText(cell).trim()).join("\t"),
      ).join("\n");
    }
    return childrenText(node);
  }

  return childrenText(template.content).replace(/^\n+|\n+$/g, "");
}
