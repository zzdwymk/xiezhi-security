import DOMPurify from "dompurify";
import { Marked, Tokenizer } from "marked";
import { localizeAiToolCodes } from "./aiPresentation";

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

export function renderMarkdown(value: string, options: { localizeToolCodes?: boolean } = {}) {
  const source = value || "";
  const cacheKey = `${options.localizeToolCodes ? "tools" : "raw"}\0${source}`;
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
  if (options.localizeToolCodes) {
    const walker = document.createTreeWalker(template.content, NodeFilter.SHOW_TEXT);
    let node: Node | null;
    while ((node = walker.nextNode())) {
      // Tool identifiers in commands, code examples, and URLs are executable evidence.
      if (!node.parentElement?.closest("pre, code, kbd, samp, a")) {
        node.textContent = localizeAiToolCodes(node.textContent || "");
      }
    }
  }
  const html = template.innerHTML;
  cache.set(cacheKey, html);
  if (cache.size > MAX_CACHE_ENTRIES)
    cache.delete(cache.keys().next().value as string);
  return html;
}
