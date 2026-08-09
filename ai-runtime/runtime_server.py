from __future__ import annotations

import argparse
import os
import sys
import traceback
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Xiezhi Local AI Runtime")
    parser.add_argument("--host", default="127.0.0.1", help="只允许回环地址")
    parser.add_argument("--port", type=int, default=8090)
    parser.add_argument("--data-dir", type=Path, default=None)
    parser.add_argument(
        "--token-file",
        type=Path,
        default=None,
        help="UTF-8 令牌文件；不要在命令行直接传令牌",
    )
    parser.add_argument(
        "--project-signing-secret-file",
        type=Path,
        default=None,
        help="UTF-8 项目签名密钥文件；不要在命令行直接传密钥",
    )
    parser.add_argument(
        "--log-level",
        choices=("critical", "error", "warning", "info"),
        default="warning",
    )
    parser.add_argument("--version", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.version:
        print("security-toolbox-ai-runtime 0.1.0")
        return 0
    if args.host not in {"127.0.0.1", "::1", "localhost"}:
        print("拒绝启动：AI Runtime 只能监听本机回环地址。", file=sys.stderr)
        return 2
    if not 1 <= args.port <= 65535:
        print("拒绝启动：端口必须在 1-65535 之间。", file=sys.stderr)
        return 2
    if args.data_dir is not None:
        data_dir = args.data_dir.expanduser().resolve()
        data_dir.mkdir(parents=True, exist_ok=True)
        os.environ["AI_RUNTIME_DATA_DIR"] = str(data_dir)
    if args.token_file is not None:
        token_path = args.token_file.expanduser().resolve()
        if not token_path.is_file():
            print("拒绝启动：令牌文件不存在。", file=sys.stderr)
            return 2
        if token_path.stat().st_size > 4096:
            print("拒绝启动：令牌文件大小异常。", file=sys.stderr)
            return 2
        token = token_path.read_text(encoding="utf-8").strip()
        if len(token) < 24:
            print("拒绝启动：AI Runtime 令牌长度至少为 24 个字符。", file=sys.stderr)
            return 2
        os.environ["AI_RUNTIME_TOKEN"] = token
    if args.project_signing_secret_file is not None:
        signing_path = args.project_signing_secret_file.expanduser().resolve()
        if not signing_path.is_file():
            print("拒绝启动：项目签名密钥文件不存在。", file=sys.stderr)
            return 2
        if signing_path.stat().st_size > 4096:
            print("拒绝启动：项目签名密钥文件大小异常。", file=sys.stderr)
            return 2
        signing_secret = signing_path.read_text(encoding="utf-8").strip()
        if len(signing_secret) < 32:
            print("拒绝启动：项目签名密钥长度至少为 32 个字符。", file=sys.stderr)
            return 2
        os.environ["AI_RUNTIME_PROJECT_SIGNING_SECRET"] = signing_secret
    os.environ["AI_RUNTIME_HOST"] = args.host
    os.environ["AI_RUNTIME_PORT"] = str(args.port)

    try:
        import uvicorn

        # Keep this import after environment/CLI processing, while making the
        # application reachable to PyInstaller's module graph.
        from app.main import app as runtime_app

        uvicorn.run(
            runtime_app,
            host=args.host,
            port=args.port,
            workers=1,
            log_level=args.log_level,
            # PyInstaller's windowed executable exposes no stdout/stderr.
            # Uvicorn's default logging config probes those streams and aborts
            # before binding a port, so the embedded runtime must not install it.
            log_config=None,
            access_log=False,
            server_header=False,
            proxy_headers=False,
        )
        return 0
    except Exception:
        # A windowed PyInstaller executable has no console. Preserve a local
        # diagnostic without environment variables, request data or tokens.
        diagnostic_root = (
            args.data_dir.expanduser().resolve() if args.data_dir else Path.cwd()
        )
        diagnostic_root.mkdir(parents=True, exist_ok=True)
        (diagnostic_root / "runtime-startup-error.log").write_text(
            traceback.format_exc(), encoding="utf-8"
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
