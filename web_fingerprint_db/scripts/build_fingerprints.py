# -*- coding: utf-8 -*-
"""
build_fingerprints.py
=====================
Parses the raw upstream rule sets in sources/ and merges them into a single,
de-duplicated, self-maintained fingerprint database written to dist/.

Outputs:
  dist/fingerprints.json            - unified record per technology (see SCHEMA)
  dist/fingerprints_wappalyzer.json - wappalyzer-compatible technology rules
  dist/stats.json                   - merge statistics

SCHEMA (dist/fingerprints.json) -- each entry:
{
  "id":         lower-case normalized technology identifier (dedup key),
  "name":       human readable name,
  "category":   list of category strings,
  "website":    optional homepage,
  "source":     list of upstream sources contributing patterns,
  "matched":    number of independent upstream sources that describe it,
  "patterns":   { "html":[...], "meta":{...}, "headers":{...},
                  "cookies":[...], "url":[...], "favicon":[...],
                  "js":[...], "body":[...] } ,
}

Patterns from multiple upstreams are merged per technology. Records are keyed
by a normalized id so re-running against updated sources cleanly re-merges.
"""

import glob
import json
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "sources")
DIST = os.path.join(ROOT, "dist")
os.makedirs(DIST, exist_ok=True)

SOURCE_NAMES = ("webappanalyzer", "fingerprinthub_v4", "fingerprinthub_v3", "whatweb")
_PAT_KEYS = ("html", "text", "css", "js", "url", "favicon", "body")

# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
_WS = re.compile(r"[\s_]+")

def normalize_id(name):
    s = str(name).strip().lower()
    s = _WS.sub("-", s)
    s = re.sub(r"[\W]+", "-", s)
    s = re.sub(r"-+", "-", s).strip("-")
    return s

def ensure_list(v):
    if v in (None, "", {}):
        return []
    if isinstance(v, list):
        return v
    if isinstance(v, (str, int, float, bool)):
        return [v]
    return []

def unique(seq):
    seen = set()
    out = []
    for x in seq:
        if x in (None, ""):
            continue
        if isinstance(x, str):
            x = x.strip()
            if not x:
                continue
        key = repr(x)
        if key not in seen:
            seen.add(key)
            out.append(x)
    return out

def merge_dict(a, b):
    out = dict(a or {})
    for k, v in (b or {}).items():
        out[k] = unique(ensure_list(out.get(k, [])) + ensure_list(v))
    return out

def merge_records(base, rec):
    """Merge a new record (from another source) into the accumulated base."""
    base["source"] = unique(base["source"] + rec["source"])
    base["matched"] = len(base["source"])
    if rec.get("website") and not base.get("website"):
        base["website"] = rec["website"]
    if not base.get("name") and rec.get("name"):
        base["name"] = rec["name"]
    base["category"] = unique(base["category"] + (rec.get("category") or []))
    for k in _PAT_KEYS:
        base["patterns"][k] = unique(
            ensure_list(base["patterns"].get(k, [])) +
            ensure_list(rec.get("patterns", {}).get(k, []))
        )
    for kd in ("headers", "cookies", "meta"):
        base["patterns"][kd] = merge_dict(
            base["patterns"].get(kd, {}) or {},
            rec.get("patterns", {}).get(kd, {}) or {},
        )
    return base

# --------------------------------------------------------------------------
# Source 1: webappanalyzer  (wappalyzer-format JSON, one file per letter)
# --------------------------------------------------------------------------
def parse_webappanalyzer():
    techdir = os.path.join(SRC, "webappanalyzer", "src", "technologies")
    out = {}
    if not os.path.isdir(techdir):
        print("[!] webappanalyzer src/technologies missing, skipping")
        return out
    for fp in sorted(glob.glob(os.path.join(techdir, "*.json"))):
        try:
            data = json.load(open(fp, encoding="utf-8"))
        except Exception as e:
            print("[!] parse error", fp, e)
            continue
        for name, rule in data.items():
            if not isinstance(rule, dict):
                continue
            nid = normalize_id(name)
            patterns = {
                "html": ensure_list(rule.get("html", "")),
                "text": ensure_list(rule.get("text", "")),
                "css": ensure_list(rule.get("css", "")),
                "js": ensure_list(rule.get("js", "")),
                "url": ensure_list(rule.get("url", "")),
                # NOTE: wappalyzer 'icon' is an ILLUSTRATION file name (e.g.
                # 'wordpress.svg'), NOT a favicon hash. It must never be used
                # as a fingerprint token, so we deliberately keep favicon empty.
                "favicon": [],
                "body": [],
                "headers": dict(rule.get("headers", {}) or {}),
                "cookies": dict(rule.get("cookies", {}) or {}),
                "meta": dict(rule.get("meta", {}) or {}),
            }
            out[nid] = {
                "id": nid,
                "name": name,
                "category": ensure_list(rule.get("cats", [])),
                "website": rule.get("website", ""),
                "source": ["webappanalyzer"],
                "matched": 1,
                "patterns": patterns,
            }
    print(f"[app ] webappanalyzer parsed: {len(out)} technologies")
    return out

# --------------------------------------------------------------------------
# Source 2: FingerprintHub v4  (Nuclei-style HTTP matchers)
# --------------------------------------------------------------------------
def parse_fingerprinthub_v4():
    fp = os.path.join(SRC, "fingerprinthub", "web_fingerprint_v4.json")
    out = {}
    if not os.path.isfile(fp):
        print("[!] fingerprinthub v4 missing, skipping")
        return out
    try:
        data = json.load(open(fp, encoding="utf-8"))
    except Exception as e:
        print("[!] fingerprinthub v4 parse error:", e)
        return out
    for item in data:
        if not isinstance(item, dict):
            continue
        info = item.get("info") or {}
        name = info.get("name") or item.get("id", "")
        nid = normalize_id(name)
        html, headers, url, body, favicon = [], {}, [], [], []
        for h in (item.get("http") or []):
            # drop the generic "{{BaseURL}}/" path which carries no signal
            for p_ in ensure_list(h.get("path", [])):
                p_ = str(p_).replace("{{BaseURL}}", "").strip("/")
                if p_:
                    url.append(p_)
            for m in (h.get("matchers") or []):
                vals = m.get("words") or m.get("regex") or m.get("dsl") or []
                if isinstance(vals, dict):
                    vals = sum((ensure_list(v) for v in vals.values()), [])
                t = m.get("type", "")
                if t == "word":
                    html.extend(ensure_list(vals))
                elif t == "regex":
                    html.extend(ensure_list(vals))
                elif t == "binary":
                    body.extend(ensure_list(vals))
                else:
                    body.extend(ensure_list(vals))
            for hk, hv in (h.get("headers") or {}).items():
                headers.setdefault(hk, [])
                headers[hk].extend(ensure_list(hv))
        if item.get("favicon-hash"):
            favicon.append(str(item.get("favicon-hash")))
        patterns = {
            "html": unique(html),
            "text": [], "css": [], "js": [],
            "url": unique(url),
            "favicon": unique(favicon),
            "body": unique(body),
            "headers": headers,
            "cookies": {},
            "meta": {},
        }
        tags = info.get("tags", "") or ""
        cat = [t.strip() for t in tags.split(",") if t.strip()]
        out[nid] = {
            "id": nid,
            "name": name or nid,
            "category": unique(cat),
            "website": "",
            "source": ["fingerprinthub_v4"],
            "matched": 1,
            "patterns": patterns,
        }
    print(f"[app ] fingerprinthub v4 parsed: {len(out)} fingerprints")
    return out

# --------------------------------------------------------------------------
# Source 3: FingerprintHub v3  (flat keyword/favicon records)
# --------------------------------------------------------------------------
def parse_fingerprinthub_v3():
    fp = os.path.join(SRC, "fingerprinthub", "web_fingerprint_v3.json")
    out = {}
    if not os.path.isfile(fp):
        print("[!] fingerprinthub v3 missing, skipping")
        return out
    try:
        data = json.load(open(fp, encoding="utf-8"))
    except Exception as e:
        print("[!] fingerprinthub v3 parse error:", e)
        return out
    for item in data:
        if not isinstance(item, dict):
            continue
        name = item.get("name", "")
        nid = normalize_id(name)
        html = []
        body = []
        for k in ("keyword", "path"):
            html.extend(ensure_list(item.get(k, [])))
        patterns = {
            "html": unique(html),
            "text": [], "css": [], "js": [],
            "url": [],
            "favicon": [str(item.get("favicon_hash"))] if item.get("favicon_hash") else [],
            "body": [],
            "headers": {},
            "cookies": {},
            "meta": {},
        }
        out[nid] = {
            "id": nid,
            "name": name or nid,
            "category": [nid],
            "website": "",
            "source": ["fingerprinthub_v3"],
            "matched": 1,
            "patterns": patterns,
        }
    print(f"[app ] fingerprinthub v3 parsed: {len(out)} fingerprints")
    return out

# --------------------------------------------------------------------------
# Source 4: WhatWeb (Ruby plugins -> extract textual/version patterns)
# --------------------------------------------------------------------------
# Regex-based, best-effort extraction of `match` arrays from each *.rb plugin.
_MATCH_ATTR_RE = re.compile(r"""([a-z0-9_]+)\s*=>\s*(?:
    "((?:[^"\\]|\\.)*)"                                  # double-quoted string
    | '(?:[^'\\]|\\.)*'                                   # single-quoted string
    | /((?:\\.|[^/\\])+)/                                # regex literal
    )""", re.VERBOSE)

def parse_whatweb():
    plugdir = os.path.join(SRC, "whatweb", "plugins")
    out = {}
    if not os.path.isdir(plugdir):
        print("[!] whatweb plugins dir missing, skipping")
        return out
    for rb in glob.glob(os.path.join(plugdir, "*.rb")):
        name = os.path.splitext(os.path.basename(rb))[0]
        try:
            text = open(rb, encoding="utf-8", errors="replace").read()
        except Exception:
            continue
        html = []
        # plugin name line:   def scan(target, opts) ... plugin named by file
        # Extract association hashes: { :regexp => /.../, :text => "...", :search => "title|headers[Server]" }
        for m in re.finditer(r"(?::?text|:?regexp|:?name|:?ghdb|:?md5|:?certainty)\s*=>\s*(?:(\"([^\"]*)\")|(/(?:[^/\\]|\\.)+/))?", text):
            pass  # simpler extraction below
        # fallback generic: grab all =~ regex / "..." string constants in a match {} block
        # whatweb patterns live in the plugin object; we take the plugin name + description
        meta = re.search(r"#\s*Description:\s*(.*)", text)
        html = []
        # collect :text=>'...' and :regexp=>/.../ string literals
        for m in re.finditer(r":(?:text|regexp)\s*=>\s*(?:'((?:[^'\\]|\\.)*)'|\"((?:[^\"\\]|\\.)*)\"|/([^/\\]+)/)", text):
            val = next((g for g in m.groups() if g), None)
            if val:
                html.append(val)
        if not html:
            continue
        nid = normalize_id(name)
        out[nid] = {
            "id": nid,
            "name": name.replace("-", " ").title(),
            "category": [nid],
            "website": "",
            "source": ["whatweb"],
            "matched": 1,
            "patterns": {
                "html": unique(html),
                "text": [], "css": [], "js": [],
                "url": [],
                "favicon": [],
                "body": [],
                "headers": {},
                "cookies": {},
                "meta": {},
            },
        }
    print(f"[app ] whatweb parsed: {len(out)} plugins")
    return out

# --------------------------------------------------------------------------
# Merge & emit
# --------------------------------------------------------------------------
def _to_regex(value):
    """wappalyzer treats a pattern as a regex if it starts with `~`, otherwise
    as a literal substring. We pass through upstream regexes (keep their `~`
    markers for wappalyzer) and escape plain literals so they are matched
    literally."""
    if value.startswith("~"):
        return value                      # already a wappalyzer regex
    return "~" + re.escape(value)         # literal string -> escaped regex

def _to_wapp_list(vals):
    """wappalyzer stores multiple patterns semicolon-separated as ONE string."""
    seq = [str(v) if isinstance(v, (str, bytes)) else json.dumps(v) for v in vals]
    return ";".join(_to_regex(v) for v in seq)

def emit_wappalyzer(merged):
    """Project our unified records into wappalyzer's `technologies` schema.

    wappalyzer's rule format uses regex strings, semicolon-joined for multiple
    patterns in a single field. `~` prefixes a full regex; otherwise it is a
    literal offset match (wappalyzer prefixes a literal with `~` internally).
    We therefore emit every pattern as a `~`-prefixed escaped regex."""
    tech = {}
    for rec in merged.values():
        p = rec["patterns"]
        rule = {}
        if p.get("html"):
            rule["html"] = _to_wapp_list(p["html"])
        if p.get("text"):
            rule["text"] = _to_wapp_list(p["text"])
        if p.get("js"):
            rule["js"] = _to_wapp_list(p["js"])
        if p.get("url"):
            rule["url"] = _to_wapp_list(p["url"])
        if p.get("meta"):
            rule["meta"] = {k: _to_wapp_list(v if isinstance(v, list) else [v]) for k, v in p["meta"].items()}
        if p.get("headers"):
            rule["headers"] = {k: _to_wapp_list(v if isinstance(v, list) else [v]) for k, v in p["headers"].items()}
        if p.get("cookies"):
            rule["cookies"] = {k: _to_wapp_list(v if isinstance(v, list) else [v]) for k, v in p["cookies"].items()}
        if rec.get("category"):
            cats = []
            for c in rec["category"]:
                try:
                    cats.append(int(c))
                except (TypeError, ValueError):
                    cats.append(c)
            rule["cats"] = cats
        if rec.get("website"):
            rule["website"] = rec["website"]
        tech[rec["name"]] = rule
    return tech

# --------------------------------------------------------------------------
# Faithfulness annotation: per-record, state plainly whether and how the rule
# can actually be matched by the server's substring-only engine.
# --------------------------------------------------------------------------
_REGEX_META2 = re.compile(r"[\\.^{}$()|[\]+\-*?/]")

def _clean_sub(value):
    if not isinstance(value, str):
        return None
    v = value.strip()
    if len(v) < 3 or _REGEX_META2.search(v):
        return None
    return v.lower()

def annotate_toolbox(rec):
    """Attach a truthful `toolbox` block describing substring-match usability.

    Keeps the original upstream patterns intact; ADDITONALKLY flags whether the
    rule would actually fire under the server engine (plain contains, no regex).
    """
    p = rec.get("patterns", {}) or {}
    body_tokens = []
    for k in ("html", "body"):
        for v in p.get(k) or []:
            tok = _clean_sub(v)
            if tok:
                body_tokens.append(tok)
    headers_tokens = {}
    for hk, hv in (p.get("headers") or {}).items():
        vals = hv if isinstance(hv, list) else [hv]
        for v in vals:
            tok = _clean_sub(v)
            if tok:
                headers_tokens.setdefault(hk.lower(), []).append(tok)
    cookies_tokens = []
    cv = p.get("cookies")
    raw_cookies = list(cv.values()) if isinstance(cv, dict) else (cv if isinstance(cv, list) else [])
    for v in raw_cookies:
        tok = _clean_sub(v)
        if tok:
            cookies_tokens.append(tok)

    # unique-ify
    body_tokens = list(dict.fromkeys(body_tokens))
    cookies_tokens = list(dict.fromkeys(cookies_tokens))

    usable = bool(body_tokens or headers_tokens or cookies_tokens)
    reasons = []
    if body_tokens:
        reasons.append("body")
    if headers_tokens:
        reasons.append("headers")
    if cookies_tokens:
        reasons.append("cookies")
    if not usable:
        # classify WHY it is unusable under the substring engine
        has_html = any((p.get(k) or []) for k in ("html", "body"))
        has_regex = any(
            (isinstance(v, str) and _REGEX_META2.search(v))
            for k in ("html", "body", "url", "js")
            for v in (p.get(k) or [])
        ) or any(
            (isinstance(v, str) and _REGEX_META2.search(v))
            for v in (p.get("favicon") or [])
        )
        if has_regex and has_html:
            reasons.append("regex_only")
        elif (p.get("favicon") or []) and not has_html:
            reasons.append("favicon_only")
        elif (p.get("url") or []) and not has_html:
            reasons.append("url_only")
        else:
            reasons.append("no_substring_tokens")

    return {
        "usable": usable,
        "dimensions": reasons,
        "body": body_tokens[:20],
        "headers": headers_tokens,
        "cookies": cookies_tokens[:10],
    }

def main():
    pools = {
        "webappanalyzer": parse_webappanalyzer(),
        "fingerprinthub_v4": parse_fingerprinthub_v4(),
        "fingerprinthub_v3": parse_fingerprinthub_v3(),
        "whatweb": parse_whatweb(),
    }

    merged = {}
    for _, pool in pools.items():
        for nid, rec in pool.items():
            if nid in merged:
                merged[nid] = merge_records(merged[nid], rec)
            else:
                merged[nid] = rec

    # sanitize: drop printable-garbage / replacement chars in display names,
    # and annotate each record with a truthful substring-matchability block.
    for nid, rec in merged.items():
        nm = rec.get("name") or nid
        cleaned = re.sub(r"[\ufffd\u0000-\u0008\u000b\u000c\u000e-\u001f]+", "", str(nm)).strip()
        rec["name"] = cleaned or nid
        rec["category"] = [c for c in rec.get("category", []) if c and "\ufffd" not in str(c)]
        rec["toolbox"] = annotate_toolbox(rec)

    # statistics
    num = len(merged)
    multi = sum(1 for r in merged.values() if r.get("matched", 1) >= 2)
    usable = sum(1 for r in merged.values() if r.get("toolbox", {}).get("usable"))
    unusable = num - usable
    per_source = {}
    for s in SOURCE_NAMES:
        per_source[s] = len(pools[s])
    stats = {
        "total_unique_technologies": num,
        "matched_by_more_than_one_source": multi,
        "usable_by_server_substring_engine": usable,
        "not_usable_by_server_substring_engine": unusable,
        "per_source_counts": per_source,
        "sources": sorted(SOURCE_NAMES),
    }

    # write unified DB (sorted by id)
    final = {k: merged[k] for k in sorted(merged)}
    with open(os.path.join(DIST, "fingerprints.json"), "w", encoding="utf-8") as f:
        json.dump(final, f, ensure_ascii=False, indent=1)

    # write wappalyzer-compatible DB (sorted by name)
    wapp = emit_wappalyzer(final)
    wapp = {k: wapp[k] for k in sorted(wapp)}
    with open(os.path.join(DIST, "fingerprints_wappalyzer.json"), "w", encoding="utf-8") as f:
        json.dump(wapp, f, ensure_ascii=False, indent=1)

    with open(os.path.join(DIST, "stats.json"), "w", encoding="utf-8") as f:
        json.dump(stats, f, ensure_ascii=False, indent=2)

    print("=" * 60)
    print(f"Total unique technologies (merged): {num:,}")
    print(f"  described by a single source:     {num - multi:,}")
    print(f"  described by multiple sources:    {multi:,}")
    print(f"  USABLE by server substring engine:{usable:,}")
    print(f"  NOT usable (regex/favicon/url):   {unusable:,}")
    for s, c in per_source.items():
        print(f"  {s:20} -> {c:,}")
    print("Wrote:", os.path.join(DIST, "fingerprints.json"))
    print("Wrote:", os.path.join(DIST, "fingerprints_wappalyzer.json"))
    print("Wrote:", os.path.join(DIST, "stats.json"))
    return stats

if __name__ == "__main__":
    main()