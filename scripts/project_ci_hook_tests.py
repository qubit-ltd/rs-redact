"""Regression tests for the local project CI hook wiring."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
HOOK = PROJECT_ROOT / ".infra" / "project-ci-check.local.sh"
EXPECTED_SCRIPTS = (
    "project_ci_hook_tests.py",
    "check_doc_examples_tests.py",
    "check_doc_examples.py",
)


class ProjectCiHookTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name) / "project"
        (self.root / ".infra").mkdir(parents=True)
        scripts = self.root / "scripts"
        scripts.mkdir()
        for name in EXPECTED_SCRIPTS:
            (scripts / name).write_text("# stub target\n", encoding="utf-8")

        shutil.copy2(HOOK, self.root / ".infra" / HOOK.name)
        self.hook = self.root / ".infra" / HOOK.name
        self.bin_directory = Path(self.temporary_directory.name) / "bin"
        self.bin_directory.mkdir()
        self.call_log = Path(self.temporary_directory.name) / "calls.jsonl"
        python_stub = self.bin_directory / "python3"
        python_stub.write_text(
            f"#!{sys.executable}\n"
            "import json, os, pathlib, sys\n"
            "with pathlib.Path(os.environ['HOOK_TEST_LOG']).open('a', encoding='utf-8') as log:\n"
            "    log.write(json.dumps(sys.argv[1:]) + '\\n')\n"
            "script = pathlib.Path(sys.argv[1]).name\n"
            "sys.exit(int(os.environ.get('HOOK_TEST_FAIL_ON', '') == script) * "
            "int(os.environ.get('HOOK_TEST_FAIL_STATUS', '0')))\n",
            encoding="utf-8",
        )
        python_stub.chmod(0o755)

    def run_hook(self, failed_script=None, failure_status=0):
        environment = os.environ.copy()
        environment["PATH"] = f"{self.bin_directory}{os.pathsep}{environment.get('PATH', '')}"
        environment["HOOK_TEST_LOG"] = str(self.call_log)
        environment.pop("PYTHONDONTWRITEBYTECODE", None)
        if failed_script is not None:
            environment["HOOK_TEST_FAIL_ON"] = failed_script
            environment["HOOK_TEST_FAIL_STATUS"] = str(failure_status)
        else:
            environment.pop("HOOK_TEST_FAIL_ON", None)
            environment.pop("HOOK_TEST_FAIL_STATUS", None)

        result = subprocess.run(
            ["bash", str(self.hook)],
            cwd=Path(self.temporary_directory.name),
            env=environment,
            check=False,
            capture_output=True,
            text=True,
        )
        calls = []
        if self.call_log.exists():
            calls = [json.loads(line) for line in self.call_log.read_text(encoding="utf-8").splitlines()]
            self.call_log.unlink()
        return result, calls

    def test_hook_runs_checks_in_order_from_outside_project(self):
        result, calls = self.run_hook()

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([Path(call[0]).name for call in calls], list(EXPECTED_SCRIPTS))
        self.assertEqual([len(call) for call in calls], [1, 1, 1])
        self.assertTrue(all(Path(call[0]).is_absolute() for call in calls))

    def test_hook_stops_and_preserves_each_python_failure(self):
        for index, (script, status) in enumerate(zip(EXPECTED_SCRIPTS, (7, 8, 9), strict=True)):
            with self.subTest(script=script):
                result, calls = self.run_hook(script, status)

                self.assertEqual(result.returncode, status, result.stderr)
                self.assertEqual([Path(call[0]).name for call in calls], list(EXPECTED_SCRIPTS[: index + 1]))


if __name__ == "__main__":
    unittest.main()
