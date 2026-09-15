# -*- coding: utf-8 -*-
"""
fetch_sources.py
================
One-command updater for the upstream fingerprint rule repositories.

This lets the fingerprint database be *self-maintaining*: re-running this
script pulls the latest rules from each upstream source so the merged
fingerprint DB can be regenerated at any time.

Upstream sources currently included:
  1. enthec/webappanalyzer   (wappalyzer-format JSON rules)   -> sources/webappanalyzer
  2. urbanadventurer/WhatWeb (Ruby plugins)                   -> sources/whatweb
  3. 0x727/FingerprintHub    (Nuclei-style web fingerprints)  -> sources/fingerprinthub

Only shallow (--depth 1) clones are made to keep bandwidth small.
"""

import os
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SOURCES = os.path.join(ROOT, "sources")

# name -> (git_url, path_under_web)
REPOS = {
    "webappanalyzer": "https://github.com/enthec/webappanalyzer.git",
    "whatweb":        "https://github.com/urbanadventurer/WhatWeb.git",
    "fingerprinthub": "https://github.com/0x727/FingerprintHub.git",
}

# For repos whose working tree sometimes fails to checkout on Windows (very
# long paths / special chars), blob-extract the rule files we actually need.
BLOB_EXTRACTS = {
    "fingerprinthub": ["web_fingerprint_v4.json", "web_fingerprint_v3.json"],
}


def run(cmd):
    print("[run]", " ".join(cmd))
    proc = subprocess.run(cmd)
    if proc.returncode != 0:
        print("[!] command failed:", " ".join(cmd))
        return False
    return True


def main():
    os.makedirs(SOURCES, exist_ok=True)
    ok = True
    for name, url in REPOS.items():
        dest = os.path.join(SOURCES, name)
        if os.path.isdir(os.path.join(dest, ".git")):
            print(f"== Updating existing clone: {name} ==")
            if not run(["git", "-C", dest, "fetch", "--depth", "1", "origin"]):
                ok = False
            run(["git", "-C", dest, "reset", "--hard", "origin/HEAD"])
            run(["git", "-C", dest, "clean", "-fd"])
        elif os.path.exists(dest):
            print(f"[!] {dest} exists but is not a git repo, removing and re-cloning")
            shutil.rmtree(dest, onerror=lambda *a: None)
            if not run(["git", "clone", "--depth", "1", url, dest]):
                ok = False
        else:
            print(f"[clone] {name} <- {url}")
            if not run(["git", "clone", "--depth", "1", url, dest]):
                ok = False
        # ensure the rule files we depend on exist in the working tree
        for blob in BLOB_EXTRACTS.get(name, []):
            blobpath = os.path.join(dest, blob)
            if not os.path.isfile(blobpath):
                print(f"[blob] extracting {blob} from HEAD")
                try:
                    data = subprocess.run(
                        ["git", "-C", dest, "cat-file", "blob", "HEAD:" + blob],
                        capture_output=True,
                    ).stdout
                    if data:
                        with open(blobpath, "wb") as fh:
                            fh.write(data)
                    else:
                        print(f"[!] blob {blob} not present in HEAD")
                        ok = False
                except Exception as e:
                    print("[!] blob extract failed", e)
                    ok = False

    if ok:
        print("All sources are up to date under:", SOURCES)
    else:
        print("Some operations failed; please check the output above.")
        sys.exit(1)


if __name__ == "__main__":
    main()