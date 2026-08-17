# -*- mode: python ; coding: utf-8 -*-
from pathlib import Path

from PyInstaller.utils.hooks import collect_all, collect_data_files, collect_dynamic_libs, collect_submodules, copy_metadata

ROOT = Path(SPECPATH)
datas = []
binaries = []
hiddenimports = [
    "app.main",
    "app.config",
    "app.graph",
    "app.indexing",
    "app.model",
    "app.schemas",
    "app.security",
    "app.tools",
]

# These libraries use namespace packages, entry points and dynamic imports.
# Explicit collection keeps the packaged executable equivalent to the tested
# Python runtime rather than silently falling back because a plugin is absent.
for package in (
    "fastapi",
    "uvicorn",
    "starlette",
    "pydantic",
    "langchain_core",
    "langgraph",
    "tiktoken",
):
    try:
        package_datas, package_binaries, package_hidden = collect_all(package)
        datas += package_datas
        binaries += package_binaries
        hiddenimports += package_hidden
    except Exception:
        hiddenimports += collect_submodules(package)

# rank_bm25 is distributed as one module rather than a package, so collecting
# package data or dynamic libraries for it only produces false warnings.
hiddenimports.append("rank_bm25")

# langchain_openai.middleware imports the top-level langchain package, which is
# intentionally not installed (see README). Collect data/binaries normally but
# filter the submodule scan so the build does not emit a false import warning.
datas += collect_data_files("langchain_openai")
binaries += collect_dynamic_libs("langchain_openai")
hiddenimports += collect_submodules(
    "langchain_openai",
    filter=lambda name: "langchain_openai.middleware" not in name,
)

for distribution in (
    "fastapi",
    "uvicorn",
    "pydantic",
    "langchain-core",
    "langchain-openai",
    "langgraph",
    "langgraph-checkpoint",
    "langgraph-prebuilt",
    "rank-bm25",
    "openai",
    "tiktoken",
):
    try:
        datas += copy_metadata(distribution)
    except Exception:
        pass

a = Analysis(
    [str(ROOT / "runtime_server.py")],
    pathex=[str(ROOT)],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter", "matplotlib", "IPython", "jupyter", "notebook", "torch", "tensorflow", "tzdata"],
    noarchive=False,
    optimize=1,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="security-toolbox-ai-runtime",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name="security-toolbox-ai-runtime",
)
