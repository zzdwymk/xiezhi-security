"""按物理行分类统计源码；需要 Pygments（已使用 2.20 版本验证）。

安装命令：python -m pip install Pygments==2.20.0
代码行指包含注释以外内容的非空行，不代表逻辑代码行数。
词法分析器用于识别注释，不验证完整程序的有效性。
使用 Python 抽象语法树识别文档字符串；普通字符串字面量仍计为代码。
预处理指令仍计为代码。
"""

import ast
import re

from pygments.lexers import get_lexer_by_name
from pygments.token import Comment
from pygments.util import ClassNotFound


LEXERS = {
    "Java": "java", "Python": "python", "Python (PyInstaller)": "python",
    "Vue": "vue", "TypeScript": "typescript", "JavaScript": "javascript",
    "TSX": "tsx", "JSX": "jsx",
    "CSS": "css", "SCSS": "scss", "Less": "less", "HTML": "html",
    "SQL": "sql", "PowerShell": "powershell", "Batch": "batch",
    "Shell": "bash", "Go": "go", "Rust": "rust", "C": "c",
    "C/C++": "cpp", "C++": "cpp", "C#": "csharp", "Kotlin": "kotlin",
    "JSON": "json", "YAML": "yaml", "XML": "xml", "TOML": "toml",
    "INI": "ini", "Properties": "properties", "Dockerfile": "docker",
    "Makefile": "make", "Requirements": "text",
}


def _python_docstring_spans(source):
    """将抽象语法树中的 UTF-8 字节列号转换为源码中的字符偏移量。"""
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError) as exc:
        raise ValueError(f"无法解析 Python 源码：{exc}") from exc
    lines = source.split("\n")
    starts = [0]
    for line in lines:
        starts.append(starts[-1] + len(line) + 1)

    def offset(line, byte_column):
        prefix = lines[line - 1].encode("utf-8")[:byte_column].decode("utf-8")
        return starts[line - 1] + len(prefix)

    for node in ast.walk(tree):
        if not isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not node.body:
            continue
        first = node.body[0]
        if (isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant)
                and isinstance(first.value.value, str)):
            yield (offset(first.lineno, first.col_offset),
                   offset(first.end_lineno, first.end_col_offset))


def classify_lines(source: str, language: str) -> dict:
    """返回总行数、空行数、非空行数、纯注释行数和代码行数；混合行计为代码。

    块注释或字符串内部的空白物理行仍计为空行。
    遇到未知语言或无效的 Python 源码时抛出 ValueError。
    Pygments 的 Error 标记保守地计为代码：这类标记常见于高亮器尚不支持的
    有效语法，例如 Vue 插槽和 Java 注解。
    独立调用本函数时也会统一 CRLF 和 CR 换行符。
    """
    source = source.replace("\r\n", "\n").replace("\r", "\n")
    alias = LEXERS.get(language)
    if alias is None:
        raise ValueError(f"未为 {language!r} 配置词法分析器")
    try:
        lexer = get_lexer_by_name(alias)
    except ClassNotFound as exc:
        raise ValueError(f"{language!r} 的 Pygments 词法分析器不可用：{alias}") from exc

    comments = bytearray(len(source))
    if language == "Requirements":
        # pip 注释从行首或空白字符后开始；URL 片段仍计为代码，
        # 例如 https://example/pkg.whl#sha256=...。
        start = 0
        for line in source.split("\n"):
            for column, char in enumerate(line):
                if char == "#" and (column == 0 or line[column - 1].isspace()):
                    comments[start + column:start + len(line)] = b"\1" * (len(line) - column)
                    break
            start += len(line) + 1
    else:
        for start, token, value in lexer.get_tokens_unprocessed(source):
            if token in Comment and token not in Comment.Preproc and token not in Comment.PreprocFile:
                comments[start:start + len(value)] = b"\1" * len(value)

    if language in {"Python", "Python (PyInstaller)"}:
        for start, end in _python_docstring_spans(source):
            comments[start:end] = b"\1" * (end - start)

    if language == "Batch":
        # Pygments 将常见 :: 注释中的第一个 ':' 和 REM 前的 '@' 视为标点。
        # 仅在词法分析器已将后续文本识别为注释时，才把这些标记也计为注释；
        # 包含相同字符的续行 echo 命令必须仍计为代码。
        for match in re.finditer(r"(?im)^[ \t]*@?(?P<body>::|rem(?:[ \t]|$))", source):
            probe = match.start("body") + (1 if match.group("body") == "::" else 0)
            if probe < len(comments) and comments[probe]:
                comments[match.start():match.end()] = b"\1" * (match.end() - match.start())

    lines = source.split("\n") if source else []
    if lines and lines[-1] == "":
        lines.pop()
    result = dict(lines=len(lines), blank=0, nonblank=0, comment=0, code=0)
    start = 0
    for line in lines:
        if not line.strip():
            result["blank"] += 1
        else:
            result["nonblank"] += 1
            has_code = any(not char.isspace() and not comments[start + i]
                           for i, char in enumerate(line))
            result["code" if has_code else "comment"] += 1
        start += len(line) + 1
    return result
