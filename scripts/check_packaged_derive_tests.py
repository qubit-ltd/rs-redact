"""Unit tests for package-checker anti-bypass behavior."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

SCRIPT = Path(__file__).with_name("check_packaged_derive.py")
SPEC = importlib.util.spec_from_file_location("check_packaged_derive", SCRIPT)
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


def summary(count):
    return f"test result: ok. {count} passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n"


class PackagedDeriveChecks(unittest.TestCase):
    def test_rejects_old_normalized_dependency(self):
        with tempfile.TemporaryDirectory() as temp:
            manifest = Path(temp) / "Cargo.toml"
            manifest.write_text('[package]\nname = "qubit-redact"\nversion = "0.10.0"\n\n[dependencies]\nqubit-redact-derive = "^0.8.1"\n')
            with self.assertRaises(CHECKER.CheckError):
                CHECKER.assert_derive_requirement(manifest)

    def test_rejects_workspace_metadata_path(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            actual = root / "worktree" / "Cargo.toml"
            with self.assertRaises(CHECKER.CheckError):
                CHECKER.assert_manifest_location(actual, root / "unpacked")

    def test_cargo_failure_is_not_swallowed(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(CHECKER.CheckError):
                CHECKER.run(["python3", "-c", "raise SystemExit(17)"], cwd=Path(temp))

    def test_accepts_positive_test_counts(self):
        for count in (1, 7, 10, 20, 100):
            with self.subTest(count=count):
                CHECKER.require_positive_test_summary(summary(count))

    def test_rejects_zero_and_missing_summaries(self):
        for output in (summary(0), "", "running 7 tests\n", "test result: ok. unknown passed"):
            with self.subTest(output=output):
                with self.assertRaises(CHECKER.CheckError):
                    CHECKER.require_positive_test_summary(output)

    def test_summary_requires_one_successful_target(self):
        CHECKER.require_positive_test_summary("log: 0 passed is only a label\n" + summary(10))
        CHECKER.require_positive_test_summary(summary(10).replace("\n", "\r\n"))
        with self.assertRaises(CHECKER.CheckError):
            CHECKER.require_positive_test_summary(summary(10) + summary(1))
        with self.assertRaises(CHECKER.CheckError):
            CHECKER.require_positive_test_summary(
                "test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out\n"
            )


if __name__ == "__main__":
    unittest.main()
