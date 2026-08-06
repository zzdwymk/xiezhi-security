# -*- mode: python ; coding: utf-8 -*-
from pathlib import Path

from PyInstaller.utils.hooks import collect_all, collect_submodules, copy_metadata

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
    "langchain",
    "langchain_core",
    "langchain_openai",
    "langgraph",
    "llama_index",
    "tiktoken",
):
    try:
        package_datas, package_binaries, package_hidden = collect_all(package)
        datas += package_datas
        binaries += package_binaries
        hiddenimports += package_hidden
    except Exception:
        hiddenimports += collect_submodules(package)

for distribution in (
    "fastapi",
    "uvicorn",
    "pydantic",
    "langchain",
    "langchain-core",
    "langchain-openai",
    "langgraph",
    "langgraph-checkpoint",
    "langgraph-prebuilt",
    "llama-index-core",
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
    excludes=["tkinter", "matplotlib", "IPython", "jupyter", "notebook", "torch", "tensorflow"],
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
