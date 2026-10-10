#!/usr/bin/env python3
"""项目代码量统计工具（需要 Python 3.9+、Git 和 Pygments 2.20.0）。

安装依赖：python -m pip install -r scripts/requirements-code-count.txt

运行示例：python scripts/count_code.py
          python scripts/count_code.py --category 业务代码
          python scripts/count_code.py --include-config --details --json reports/code-count.json

有效代码行：剔除空行和纯注释行，Python 文档字符串按注释处理。
同一行既有代码又有注释时计为代码；字符串、括号、模板和样式仍计为代码。
采用词法分析统计物理行，不等同于逻辑语句数或完整编译分析。
按业务代码、测试代码、维护脚本、配置文件分类，并分别按语言汇总。
默认纳入 .spec、vite.config.ts 等可执行构建配置；
--include-config 可额外纳入 JSON、YAML 等配置文件。
范围为 Git 已跟踪文件及未被忽略的新文件，读取当前工作区内容。
默认排除依赖、第三方工具、构建产物、文档和数据文件。
"""

import argparse
from collections import defaultdict
from datetime import datetime, timezone
from fnmatch import fnmatchcase
import json
from pathlib import Path
import subprocess
import sys
import unicodedata

if __name__ == "__main__":
    # 统一重定向和终端输出编码，避免 Windows 默认编码导致中文乱码。
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")

try:
    import pygments
    from code_line_metrics import classify_lines
except ModuleNotFoundError as exc:
    if exc.name and exc.name.startswith("pygments"):
        sys.exit("缺少 Pygments，请运行：python -m pip install Pygments==2.20.0")
    raise


LANGUAGES = {
    ".java": "Java", ".py": "Python", ".spec": "Python (PyInstaller)",
    ".vue": "Vue", ".ts": "TypeScript", ".tsx": "TSX",
    ".js": "JavaScript", ".cjs": "JavaScript", ".mjs": "JavaScript",
    ".jsx": "JSX", ".css": "CSS", ".scss": "SCSS", ".less": "Less",
    ".html": "HTML", ".htm": "HTML", ".sql": "SQL",
    ".ps1": "PowerShell", ".psm1": "PowerShell",
    ".cmd": "Batch", ".bat": "Batch", ".sh": "Shell",
    ".go": "Go", ".rs": "Rust", ".c": "C", ".h": "C/C++",
    ".cpp": "C++", ".hpp": "C++", ".cs": "C#", ".kt": "Kotlin",
}
CONFIG_LANGUAGES = {
    ".json": "JSON", ".yaml": "YAML", ".yml": "YAML", ".xml": "XML",
    ".toml": "TOML", ".ini": "INI", ".properties": "Properties",
}
EXCLUDED_DIRS = {
    ".git", ".idea", ".vscode", ".run", ".tmp", ".codex", ".agents",
    "node_modules", ".venv", "venv", "__pycache__", ".pytest_cache",
    ".mypy_cache", ".ruff_cache", ".tox", ".nox", "target", "dist",
    "build", "desktop-release", "coverage", "htmlcov", "BOOT-INF",
    "data", "logs", "docs", "reports", "test-results", "playwright-report",
    "e2e-evidence", "e2e-artifacts", "test-data", ".downloads",
}
EXCLUDED_PATHS = (
    "security-toolbox-web/tools/*",  # 随项目附带的 ZAP 等第三方扫描工具。
    "security-toolbox-server/src/main/resources/fingerprints/*.json",
    "security-toolbox-web/vite.config.js",
    "security-toolbox-web/vite.config.d.ts",
)
EXCLUDED_FILES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "composer.lock",
    ".toolbox-build-manifest.json",
}
METRICS = ("files", "lines", "blank", "comment", "code", "nonblank")
CATEGORY_LABELS = {
    "Business": "业务代码", "Test": "测试代码",
    "Maintenance": "维护脚本", "Configuration": "配置文件",
}
METRIC_LABELS = {
    "files": "文件数", "lines": "总行数", "blank": "空行数",
    "comment": "纯注释行", "code": "有效代码行", "nonblank": "非空行数",
}
DISPLAY_LABELS = {
    **CATEGORY_LABELS, "(root)": "项目根目录", "TOTAL": "总计",
    "Batch": "批处理", "Python (PyInstaller)": "Python（打包配置）",
    "Requirements": "依赖清单", "Properties": "属性配置",
}
TEST_EXCEPTIONS = {
    "security-toolbox-web/el-tooltip-test.html",
    "security-toolbox-web/scripts/ai-relay-runtime-probe.py",
    "security-toolbox-web/scripts/verify-offline-tools.cjs",
    "security-toolbox-web/scripts/visual-smoke.cjs",
}


def category(relative):
    """根据项目路径规则分类，不判断代码作者或原创性。"""
    path = Path(relative)
    if (path.suffix.lower() in CONFIG_LANGUAGES or path.suffix == ".spec"
            or path.name in {"vite.config.ts", "Dockerfile", "Makefile"}
            or fnmatchcase(path.name, "requirements*.txt")):
        return "Configuration"
    if (set(path.parts[:-1]) & {"test", "tests", "__tests__"}
            or path.name.startswith(("test_", "test-"))
            or any(part in path.name for part in (".test.", ".spec."))
            or relative in TEST_EXCEPTIONS):
        return "Test"
    if ("scripts" in path.parts[:-1]
            or path.suffix.lower() in {".cmd", ".bat", ".ps1", ".psm1", ".sh"}
            or relative == "security-toolbox-web/electron/dev-runner.cjs"):
        return "Maintenance"
    return "Business"


def candidates(root):
    """采用 Git 忽略规则，使用 -z 保留文件名中的空格和中文。"""
    result = subprocess.run(
        ["git", "-C", str(root), "ls-files", "--cached", "--others",
         "--exclude-standard", "-z", "--", "."],
        check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    return sorted(set(result.stdout.decode("utf-8").split("\0")) - {""})


def excluded(relative, patterns):
    path = Path(relative)
    return (
        bool(set(path.parts[:-1]) & EXCLUDED_DIRS)
        or path.name in EXCLUDED_FILES
        or path.name.endswith((".min.js", ".min.css"))
        or any(fnmatchcase(relative, pattern) for pattern in (*EXCLUDED_PATHS, *patterns))
    )


def count_file(path, language):
    data = path.read_bytes()
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        source = data.decode("utf-16")
    else:
        try:
            source = data.decode("utf-8-sig")
        except UnicodeDecodeError:
            source = data.decode("gb18030")
    if "\0" in source:
        raise ValueError("源文件中包含二进制内容")
    return dict(files=1, **classify_lines(source, language))


def summarize(rows, key):
    groups = defaultdict(lambda: dict.fromkeys(METRICS, 0))
    for row in rows:
        for metric in METRICS:
            groups[row[key]][metric] += row[metric]
    return dict(sorted(groups.items()))


def display_width(value):
    """按终端显示宽度计算，中日韩全角字符占两列。"""
    return sum(0 if unicodedata.combining(char) else
               2 if unicodedata.east_asian_width(char) in "WF" else 1 for char in value)


def padded(value, width, right=False):
    spaces = " " * max(0, width - display_width(value))
    return spaces + value if right else value + spaces


def print_table(title, groups):
    width = max([display_width(DISPLAY_LABELS.get(name, name)) for name in groups] + [12])
    print(f"\n{title}\n" + padded("名称", width) + " " + " ".join(
        padded(METRIC_LABELS[k], 7 if k == "files" else 10, right=True) for k in METRICS))
    for name, counts in groups.items():
        print(padded(DISPLAY_LABELS.get(name, name), width) + " " + " ".join(
            f"{counts[k]:>{7 if k == 'files' else 10},}" for k in METRICS))


class ChineseHelpFormatter(argparse.RawDescriptionHelpFormatter):
    def add_usage(self, usage, actions, groups, prefix=None):
        super().add_usage(usage, actions, groups, prefix or "用法：")


class ChineseArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        for original, translated in {
            "unrecognized arguments:": "无法识别的参数：",
            "expected one argument": "需要提供一个值",
            "argument ": "参数 ",
            "ignored explicit argument": "不接受附加值",
        }.items():
            message = message.replace(original, translated)
        self.print_usage(sys.stderr)
        self.exit(2, f"参数错误：{message}\n")


def parse_category(value):
    aliases = {label: key for key, label in CATEGORY_LABELS.items()}
    result = aliases.get(value, value)
    if result not in CATEGORY_LABELS:
        raise argparse.ArgumentTypeError("类别须为：业务代码、测试代码、维护脚本、配置文件（也兼容原英文类别）")
    return result


def main():
    parser = ChineseArgumentParser(description=__doc__, formatter_class=ChineseHelpFormatter, add_help=False)
    parser._optionals.title = "可选参数"
    parser.add_argument("-h", "--help", action="help", help="显示帮助信息并退出")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1], metavar="项目目录", help="Git 项目目录，默认使用脚本所在项目")
    parser.add_argument("--include-config", action="store_true", help="额外统计 JSON/YAML/XML/TOML/INI/properties 和依赖清单")
    parser.add_argument("--exclude", action="append", default=[], metavar="匹配规则", help="额外排除的相对路径通配符，可重复，例如 '*/tests/*'")
    parser.add_argument("--details", action="store_true", help="显示每个文件的统计明细")
    parser.add_argument("--category", type=parse_category, metavar="类别", help="仅统计指定类别：业务代码、测试代码、维护脚本、配置文件；兼容原英文值")
    parser.add_argument("--json", type=Path, metavar="输出路径", help="导出 JSON 报告，包含逐文件统计")
    args = parser.parse_args()
    root = args.root.resolve()
    languages = {**LANGUAGES, **(CONFIG_LANGUAGES if args.include_config else {})}
    rows, errors = [], []
    try:
        paths = candidates(root)
    except (OSError, subprocess.CalledProcessError, UnicodeError) as exc:
        parser.exit(2, f"无法列出源文件，请确认已安装 Git，且指定目录属于 Git 项目。\n详细信息：{exc}\n")
    for relative in paths:
        if excluded(relative, args.exclude):
            continue
        path = root / relative
        language = languages.get(path.suffix.lower())
        if path.name in {"Dockerfile", "Makefile"}:
            language = path.name
        if args.include_config and fnmatchcase(path.name, "requirements*.txt"):
            language = "Requirements"
        if not language or path.is_symlink() or not path.exists():
            continue
        file_category = category(relative)
        if args.category and args.category != file_category:
            continue
        try:
            counts = count_file(path, language)
        except (OSError, UnicodeError, ValueError) as exc:
            errors.append({"path": relative, "error": str(exc)})
            continue
        module = relative.split("/", 1)[0] if "/" in relative else "(root)"
        rows.append(dict(path=relative, language=language, module=module, category=file_category, **counts))
    by_language = summarize(rows, "language")
    by_module = summarize(rows, "module")
    by_category = summarize(rows, "category")
    by_category_language = {
        group: summarize([row for row in rows if row["category"] == group], "language")
        for group in by_category
    }
    business_by_module = summarize([row for row in rows if row["category"] == "Business"], "module")
    total = {key: sum(row[key] for row in rows) for key in METRICS}
    print(f"项目目录：{root}\n统计范围：Git 已跟踪文件及未被忽略的新文件，包含源码、测试和脚本")
    print(f"额外纳入配置文件：{'是' if args.include_config else '否'}；可执行构建配置默认计入")
    print("有效代码行剔除空行和纯注释行（包括 Python 文档字符串）。")
    print("代码与注释混合行计为代码；模板、样式、括号和字符串仍保留，按物理行统计。")
    print(f"词法分析器：Pygments {pygments.__version__}；类别：{CATEGORY_LABELS.get(args.category, '全部')}")
    print_table("按用途分类", by_category)
    print_table("业务代码按模块统计", business_by_module)
    print_table("按语言统计", by_language)
    for group, language_counts in by_category_language.items():
        print_table(f"{CATEGORY_LABELS[group]}：按语言统计", language_counts)
    print_table("按模块统计", by_module)
    print_table("全部汇总", {"TOTAL": total})
    if args.details:
        print_table("逐文件明细", {row["path"]: row for row in rows})
    if args.json:
        report = dict(root=str(root), generated_at=datetime.now(timezone.utc).isoformat(),
                      metric="有效物理代码行：剔除空行和纯注释行；混合行计为代码；Python 文档字符串按注释处理",
                      limitations="基于词法分析，不是完整编译分析。模板、样式、括号和字符串仍计为代码。按项目路径规则分类，不判断原创性。",
                      labels=dict(metrics=METRIC_LABELS, categories=CATEGORY_LABELS),
                      pygments_version=pygments.__version__, category_filter=args.category,
                      include_config=args.include_config,
                      exclusions=dict(directories=sorted(EXCLUDED_DIRS),
                                      paths=[*EXCLUDED_PATHS, *args.exclude],
                                      filenames=sorted(EXCLUDED_FILES),
                                      minified=["*.min.js", "*.min.css"], gitignore=True),
                      total=total, by_language=by_language, by_module=by_module,
                      by_category=by_category, business_by_module=business_by_module,
                      by_category_language=by_category_language,
                      files=rows, errors=errors)
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"\nJSON 报告已保存：{args.json.resolve()}")
    for error in errors:
        print(f"警告：{error['path']}：{error['error']}", file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
