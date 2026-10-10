"""Regression checks for project scope and exported code-count reports."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import count_code


class CategoryTests(unittest.TestCase):
    def test_project_categories_and_exceptions(self):
        examples = {
            "Business": [
                "security-toolbox-server/src/main/java/com/bachelor/toolbox/auth/SecurityConfig.java",
                "security-toolbox-web/src/env.d.ts",
                "security-toolbox-web/src/views/Tasks.vue",
                "security-toolbox-web/electron/main.cjs",
                "security-toolbox-web/electron/startup.html",
                "security-toolbox-web/index.html",
                "ai-runtime/app/config.py",
                "ai-runtime/runtime_server.py",
            ],
            "Test": [
                "security-toolbox-server/src/test/java/com/bachelor/toolbox/auth/AuthTests.java",
                "ai-runtime/tests/mock_openai_server.py",
                "security-toolbox-web/tests/e2e/lib/harness.cjs",
                "security-toolbox-web/tests/e2e/gen-report.cjs",
                "security-toolbox-web/scripts/test-ai-relay.cjs",
                "security-toolbox-web/scripts/ai-relay-runtime-probe.py",
                "security-toolbox-web/scripts/verify-offline-tools.cjs",
                "security-toolbox-web/scripts/visual-smoke.cjs",
                "security-toolbox-web/el-tooltip-test.html",
            ],
            "Maintenance": [
                "scripts/count_code.py",
                "security-toolbox-web/scripts/generate-icon.cjs",
                "security-toolbox-web/electron/dev-runner.cjs",
                "ai-runtime/build-windows.ps1",
                "ai-runtime/run.cmd",
                "start-all.cmd",
                "web_fingerprint_db/scripts/build_fingerprints.py",
            ],
            "Configuration": [
                "ai-runtime/ai-runtime.spec",
                "security-toolbox-web/vite.config.ts",
                "security-toolbox-web/tsconfig.json",
                "security-toolbox-server/src/main/resources/xray/config.yaml",
                "ai-runtime/requirements-build.txt",
            ],
        }
        for expected, paths in examples.items():
            for path in paths:
                with self.subTest(path=path):
                    self.assertEqual(count_code.category(path), expected)

    def test_dependencies_generated_files_and_custom_exclusions(self):
        for path in (
            "security-toolbox-web/node_modules/package/index.js",
            "security-toolbox-server/target/generated/Main.java",
            "web_fingerprint_db/dist/fingerprints.json",
            "security-toolbox-web/tools/zap/zap.bat",
            "security-toolbox-web/vite.config.js",
            "security-toolbox-web/vite.config.d.ts",
            "security-toolbox-server/src/main/resources/fingerprints/default-rules.json",
            "security-toolbox-web/package-lock.json",
            "security-toolbox-web/src/vendor.min.js",
            "reports/report.html",
        ):
            with self.subTest(path=path):
                self.assertTrue(count_code.excluded(path, []))
        self.assertFalse(count_code.excluded("security-toolbox-web/src/env.d.ts", []))
        self.assertTrue(count_code.excluded("ai-runtime/tests/test_runtime.py", ["*/tests/*"]))
        self.assertFalse(count_code.excluded("ai-runtime/app/main.py", ["*/tests/*"]))


class GitScopeAndReportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.git("init", "-q")
        self.write("tracked.py", "# previous version\nvalue = 1\n")
        self.git("add", "tracked.py")
        # Already tracked files remain candidates even after an ignore rule is added.
        self.write(".gitignore", "tracked.py\nignored.py\n")
        self.write("ignored.py", "should_not_count = 1\n")
        self.write("未跟踪 source.py", "fresh = 1\n")

    def git(self, *args):
        return subprocess.run(
            ["git", "-C", str(self.root), *args],
            check=True, capture_output=True,
        )

    def write(self, relative, source):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")

    def report(self, *args):
        destination = self.root / "reports" / "count.json"
        completed = subprocess.run(
            [sys.executable, str(Path(count_code.__file__).resolve()),
             "--root", str(self.root), "--json", str(destination), *args],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        return json.loads(destination.read_text(encoding="utf-8"))

    def test_git_candidates_include_unicode_and_tracked_ignored_files(self):
        candidates = count_code.candidates(self.root)
        self.assertEqual(candidates, [".gitignore", "tracked.py", "未跟踪 source.py"])

    def test_json_uses_working_tree_and_separates_code_from_comments(self):
        self.write("tracked.py", '# explanatory comment\n\nvalue = "# literal"  # mixed line\nother = 2\n')
        self.write("scripts/test_scope.py", "# test support\nassert 1 == 1\n")
        self.write("scripts/build.py", "print('build')\n")
        self.write("config.json", '{"enabled": true}\n')
        self.write("node_modules/dependency.js", "dependency();\n")
        report = self.report()
        rows = {row["path"]: row for row in report["files"]}
        self.assertEqual(set(rows), {"tracked.py", "未跟踪 source.py", "scripts/test_scope.py", "scripts/build.py"})
        expected = dict(files=1, lines=4, blank=1, comment=1, code=2, nonblank=3)
        self.assertEqual({key: rows["tracked.py"][key] for key in expected}, expected)
        self.assertEqual(report["by_category"]["Business"]["code"], 3)
        self.assertEqual(report["by_category"]["Test"]["code"], 1)
        self.assertEqual(report["by_category"]["Maintenance"]["code"], 1)
        self.assertEqual(report["errors"], [])
        self.assertIn("Python 文档字符串", report["metric"])
        self.assertTrue(report["exclusions"]["gitignore"])
        for metric in count_code.METRICS:
            self.assertEqual(report["total"][metric], sum(row[metric] for row in rows.values()))
        for row in rows.values():
            self.assertEqual(row["lines"], row["blank"] + row["comment"] + row["code"])
            self.assertEqual(row["nonblank"], row["comment"] + row["code"])

    def test_configuration_and_category_filters_are_recorded(self):
        self.write("config.json", '{"enabled": true}\n')
        self.write("scripts/requirements-build.txt", "Pygments==2.20.0\n")
        report = self.report("--include-config", "--category", "Configuration")
        self.assertEqual({row["path"] for row in report["files"]}, {"config.json", "scripts/requirements-build.txt"})
        self.assertTrue(report["include_config"])
        self.assertEqual(report["category_filter"], "Configuration")
        self.assertEqual(report["business_by_module"], {})
        report = self.report("--exclude", "tracked.py")
        self.assertNotIn("tracked.py", {row["path"] for row in report["files"]})
        self.assertIn("tracked.py", report["exclusions"]["paths"])


if __name__ == "__main__":
    unittest.main()
