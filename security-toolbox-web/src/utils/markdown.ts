import DOMPurify from "dompurify";
import { marked } from "marked";

const cache = new Map<string, string>();
const MAX_CACHE_ENTRIES = 200;

marked.setOptions({ gfm: true, breaks: true });

export function renderMarkdown(value: string) {
  const source = value || "";
  const cached = cache.get(source);
  if (cached !== undefined) return cached;

  const raw = marked.parse(source) as string;
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
  const html = template.innerHTML;
  cache.set(source, html);
  if (cache.size > MAX_CACHE_ENTRIES)
    cache.delete(cache.keys().next().value as string);
  return html;
}
