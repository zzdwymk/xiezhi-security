# -*- coding: utf-8 -*-
"""
export_toolbox.py
=================
Exports the merged fingerprint DB (dist/fingerprints.json) into the server's
built-in EHole-style rule file:

    security-toolbox-server/src/main/resources/fingerprints/default-rules.json

Server-side hard constraints (FingerprintRuleCatalog.java):
  * matcher uses plain CONTAINS substring matching (NO regex),
  * a rule fires only when EVERY configured dimension AND EVERY value inside a
    dimension matches (strict AND semantics),
  * catalog limit: <= 10000 rules AND file <= 2 MiB,
  * id must match `[a-z0-9][a-z0-9._-]{0,79}` and be unique.

Strategy (high-confidence, low false-positive):
  * keep records described by >= 2 upstream sources when possible,
  * keep only substring-safe (non-regex) patterns, lower-cased,
  * emit a SINGLE strongest candidate per supported dimension so the AND
    semantics do not make the rule effectively fire-proof,
  * map richer fields onto supported Rule fields; drop url/js/meta which the
    engine does not evaluate.
"""

import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DIST = os.path.join(ROOT, "dist")
PROJECT = os.path.dirname(ROOT)  # Graduation_Project
PROJECT_ROOT = PROJECT
DEFAULT_RULES = os.path.join(
    PROJECT,
    "security-toolbox-server",
    "src",
    "main",
    "resources",
    "fingerprints",
    "default-rules.json",
)

MAX_RULES = 10_000
MAX_BYTES = 2 * 1024 * 1024
NEW_VERSION = "2026.09.14-expanded"

# regex metacharacters that make a substring-match useless or misleading
_REGEX_META = re.compile(r"[\\.^{}$()|[\]+\-*?/]")
# favicon faviconMd5 values are MD5 hashes -> 32 lowercase hex chars
_MD5_HEX = re.compile(r"^[0-9a-f]{32}$")

CATEGORY_MAP = {
    "webserver": "WEB_SERVER",
    "language": "LANGUAGE",
    "framework": "FRAMEWORK",
    "cms": "CMS",
    "frontend": "FRONTEND",
    "panel": "PANEL",
    "devops": "DEVOPS",
    "middleware": "MIDDLEWARE",
    "api": "API",
    "monitor": "MONITOR",
    "mail": "MAIL",
    "oa": "OA",
    "securitydevice": "SECURITY_DEVICE",
    "cdn": "CDN_WAF",
    "waf": "CDN_WAF",
    "crm": "APPLICATION",
}
DEFAULT_CATEGORY = "EHOLE"


def is_substring_clean(value):
    return not _REGEX_META.search(value)


def nice_substrings(values):
    """Substring-safe, lower-cased candidates; drop regex-y/too-short/noise."""
    out = []
    for v in values or []:
        if not isinstance(v, str):
            continue
        s = str(v).strip()
        if len(s) < 3:
            continue
        if not is_substring_clean(s):
            continue
        out.append(s.lower())
    # greedy de-duplicate: drop candidates that are substrings of a longer one
    dedup = []
    for s in sorted(set(out), key=len, reverse=True):
        if not any(s in t and s != t for t in dedup):
            dedup.append(s)
    return dedup


def map_category(cats):
    for c in cats or []:
        key = str(c).strip().lower()
        for k, mapped in CATEGORY_MAP.items():
            if k in key or key.startswith(k):
                return mapped
    return DEFAULT_CATEGORY


def _pristine_base():
    """Read the repository's ORIGINAL built-in rules (the ones shipped with the
    project, before any export run) straight from git HEAD. Using the pristine
    set as the base keeps this export IDEMPOTENT: re-running does not append a
    second time, so rule count never drifts upward."""
    rel = os.path.relpath(DEFAULT_RULES, PROJECT).replace("\\", "/")
    try:
        data = subprocess.run(
            ["git", "-C", PROJECT_ROOT, "show", "HEAD:" + rel],
            capture_output=True,
        ).stdout
    except Exception:
        data = b""
    if not data:
        print("[!] cannot read pristine rules from git HEAD; aborting")
        sys.exit(1)
    return json.loads(data.decode("utf-8"))


def build():
    base = _pristine_base()
    existing_rules = base.get("rules", [])
    seen = {r["id"] for r in existing_rules if isinstance(r, dict)}

    lib = json.load(open(os.path.join(DIST, "fingerprints.json"), encoding="utf-8"))

    # candidate records: mapped to Rule dims. Use the unified library's
    # 'toolbox' annotation as the single source of truth (same criteria that
    # produced it), so the exported rules stay exactly faithful to it.
    candidates = []
    for rec in lib.values():
        nid = rec.get("id")
        if not nid or not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,79}", nid):
            continue
        matched = int(rec.get("matched", 1))
        tb = rec.get("toolbox", {}) or {}
        if not tb.get("usable"):
            continue

        # per dimension, pick the STRONGEST single candidate so the server's
        # AND semantics do not make the rule effectively impossible to fire
        body = (tb.get("body") or [])[:1]
        headers = {}
        for hk, hv in (tb.get("headers") or {}).items():
            if hv:
                headers[hk.lower()] = [hv[0]]
        cookies = (tb.get("cookies") or [])[:1]

        favicon_md5 = []
        for v in rec.get("patterns", {}).get("favicon", []) or []:
            s = str(v).strip().lower()
            if _MD5_HEX.fullmatch(s):
                favicon_md5.append(s)

        dims = {}
        if headers:
            dims["headers"] = headers
        if cookies:
            dims["cookies"] = cookies
        if body:
            dims["body"] = body
        if favicon_md5:
            dims["faviconMd5"] = favicon_md5[:2]

        # Skip rules that would rely ONLY on a favicon hash: they rarely fire
        # (favicon availability/caching) and only burn quota.
        if not dims or set(dims) == {"faviconMd5"}:
            continue

        # score for prioritisation: more sources + more evidence == higher confidence
        candidates.append((nid, rec, matched, sum(len(v) for v in dims.values()), dims))

    # sort: confident (multi-source) first; keep high-signal rules
    candidates.sort(key=lambda c: (int(c[2]) >= 2, c[3]), reverse=True)

    new_records = []
    for nid, rec, matched, _signal, dims in candidates:
        if len(existing_rules) + len(new_records) >= MAX_RULES:
            break
        if nid in seen:
            continue
        seen.add(nid)
        cat = map_category(rec.get("category", []))
        rule = {
            "id": nid,
            "name": (rec.get("name") or nid)[:60],
            "category": cat,
            "confidence": 90 if matched >= 2 else 75,
        }
        rule.update(dims)
        new_records.append(rule)

    merged = existing_rules + new_records
    out = {"version": NEW_VERSION, "rules": merged}
    payload = json.dumps(out, ensure_ascii=False)
    data = payload.encode("utf-8")
    if len(data) > MAX_BYTES:
        # try to trim from the tail (longest single-source noise) until it fits
        while len(data) > MAX_BYTES and new_records:
            dropped = new_records.pop()
            seen.discard(dropped["id"])
            merged = existing_rules + new_records
            out = {"version": NEW_VERSION, "rules": merged}
            payload = json.dumps(out, ensure_ascii=False)
            data = payload.encode("utf-8")

    if len(data) > MAX_BYTES:
        print(f"[!] still exceeds 2MiB after trimming ({len(data)} bytes); aborting without write")
        sys.exit(1)

    with open(DEFAULT_RULES, "w", encoding="utf-8") as f:
        f.write(payload + "\n")

    print(f"Existing rules kept : {len(existing_rules)}")
    print(f"New rules added     : {len(new_records)}")
    print(f"Total rules         : {len(merged)}")
    print(f"File size           : {len(data)/1024:.1f} KiB (limit 2048 KiB)")
    print("Wrote:", DEFAULT_RULES)


if __name__ == "__main__":
    build()