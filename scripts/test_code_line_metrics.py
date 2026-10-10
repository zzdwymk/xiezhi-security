"""Run: python -m unittest discover -s scripts -p test_code_line_metrics.py"""

import unittest

from code_line_metrics import LEXERS, classify_lines


class LineMetricsTests(unittest.TestCase):
    def check(self, source, language, code, comment, blank=0):
        result = classify_lines(source, language)
        self.assertEqual(result, dict(lines=code + comment + blank, code=code,
                                     comment=comment, blank=blank, nonblank=code + comment))

    def test_string_markers_and_mixed_comments(self):
        self.check('const url = "https://host/#part"; // tail\n'
                   '// full comment\n/* block\n\nend */ const y = "/*";\n',
                   "JavaScript", code=2, comment=2, blank=1)

    def test_python_docstrings_and_assigned_strings(self):
        self.check('"""module doc\nsecond line\n"""\n'
                   'DATA = """ordinary\n# still a string\n"""\n'
                   'def f():\n    """function doc"""\n    return "#" # tail\n'
                   'class C:\n    """class doc"""\n    pass\n',
                   "Python", code=7, comment=5)

    def test_python_non_doc_expression_and_unicode_columns(self):
        self.check('def 函数(): "文档"\nx = 1\n"not a docstring"\n',
                   "Python", code=3, comment=0)

    def test_python_parenthesized_docstring(self):
        self.check('(\n "doc"\n)\n', "Python", code=0, comment=3)

    def test_vue_sections(self):
        self.check('<template>\n<!-- template comment -->\n<p>Hello</p>\n</template>\n'
                   '<script setup lang="ts">\n// script comment\nconst x = "//"\n</script>\n'
                   '<style scoped>\n/* style comment */\n.a { color: red; }\n</style>\n',
                   "Vue", code=9, comment=3)

    def test_preprocessor(self):
        self.check('#include <stdio.h>\n#define COUNT 1\n// comment\n',
                   "C", code=2, comment=1)

    def test_java_text_blocks(self):
        self.check('String query = """\n// literal\n/* literal */\n""";\n// comment\n',
                   "Java", code=4, comment=1)

    def test_typescript_generics(self):
        self.check('const values: Map<string, number> = new Map();\n// comment\n',
                   "TypeScript", code=1, comment=1)

    def test_shell_heredoc(self):
        self.check('cat <<EOF\n# literal\nEOF\n# comment\n',
                   "Shell", code=3, comment=1)

    def test_powershell_comments_strings_and_here_strings(self):
        self.check('# comment\n<# block\n\nend #>\n'
                   '$value = "# literal <#" # tail\n'
                   "$text = @'\n# literal\n<# literal #>\n'@\n",
                   "PowerShell", code=5, comment=3, blank=1)

    def test_batch_rem_and_double_colon(self):
        self.check('@echo off\nREM comment\nrem another comment\n:: comment\n  @REM hidden comment\n'
                   'echo "REM :: literal"\n',
                   "Batch", code=2, comment=4)

    def test_batch_continuation(self):
        self.check('echo first ^\n:: continued\n', "Batch", code=2, comment=0)

    def test_html_embedded_js_css(self):
        self.check('<!-- html comment -->\n<script>\n// js comment\n'
                   'const value = "// # literal";\n</script>\n'
                   '<style>\n/* css comment */\n.x { content: "/* # literal */"; }\n</style>\n',
                   "HTML", code=6, comment=3)

    def test_js_regex_and_template_literals(self):
        self.check('const pattern = /https?:\\/\\/[^#]+/; // tail\n'
                   'const text = `\n// literal\n# literal\n/* literal */\n`;\n'
                   '// comment\n',
                   "JavaScript", code=6, comment=1)

    def test_blank_and_newlines(self):
        self.check('', "Python", code=0, comment=0)
        self.check('\r\n# comment\rx=1', "Python", code=1, comment=1, blank=1)
        self.check('/*\n \n*/', "Java", code=0, comment=2, blank=1)

    def test_requirements(self):
        self.check('# heading\nthing==1 # tail\nhttps://host/file#sha256=abc\n',
                   "Requirements", code=2, comment=1)

    def test_errors(self):
        with self.assertRaises(ValueError):
            classify_lines('x', "Unknown")
        with self.assertRaises(ValueError):
            classify_lines('def broken(', "Python")

    def test_all_explicit_lexers_available(self):
        for language in LEXERS:
            with self.subTest(language=language):
                self.check('', language, code=0, comment=0)


if __name__ == "__main__":
    unittest.main()
