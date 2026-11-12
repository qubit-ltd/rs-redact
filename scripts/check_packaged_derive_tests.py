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
    DOCUMENTS = {
        "README.md": "en",
        "README.zh_CN.md": "zh",
        "doc/user_guide.md": "en",
        "doc/user_guide.zh_CN.md": "zh",
    }

    def _documentation_fixture(self, root, *, english=True, chinese=True):
        tag = f"v{CHECKER.RUNTIME_VERSION}"
        english_target = f"https://github.com/qubit-ltd/rs-redact/blob/{tag}/derive/README.md"
        chinese_target = f"https://github.com/qubit-ltd/rs-redact/blob/{tag}/derive/README.zh_CN.md"
        for source_name, language in self.DOCUMENTS.items():
            target = english_target if language == "en" else chinese_target
            if source_name == "README.md" and not english:
                target = "derive/README.md"
            if source_name == "README.zh_CN.md" and not chinese:
                target = "https://github.com/qubit-ltd/rs-redact/blob/main/derive/README.md"
            source = root / source_name
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_text(f"[derive]({target})\n[derive again]({target})\n", encoding="utf-8")

    def _expected_target(self, source_name):
        language_path = "README.zh_CN.md" if source_name.endswith("zh_CN.md") else "README.md"
        return f"https://github.com/qubit-ltd/rs-redact/blob/v{CHECKER.RUNTIME_VERSION}/derive/{language_path}"

    def test_published_documentation_links_resolve_inside_package(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self._documentation_fixture(root)
            CHECKER.assert_published_documentation(root)

    def test_both_published_guides_are_required(self):
        for source_name in ("doc/user_guide.md", "doc/user_guide.zh_CN.md"):
            with self.subTest(source=source_name):
                with tempfile.TemporaryDirectory() as temp:
                    root = Path(temp)
                    self._documentation_fixture(root)
                    (root / source_name).unlink()
                    with self.assertRaises(CHECKER.CheckError) as raised:
                        CHECKER.assert_published_documentation(root)
                    self.assertIn(source_name, str(raised.exception))
                    self.assertIn(self._expected_target(source_name), str(raised.exception))

    def test_published_guides_reject_stale_derive_targets(self):
        tag = f"v{CHECKER.RUNTIME_VERSION}"
        for source_name in ("doc/user_guide.md", "doc/user_guide.zh_CN.md"):
            expected = self._expected_target(source_name)
            wrong_language = "README.md" if source_name.endswith("zh_CN.md") else "README.zh_CN.md"
            invalid_targets = {
                "local relative": "../derive/README.md",
                "floating main": f"https://github.com/qubit-ltd/rs-redact/blob/main/derive/{expected.rsplit('/', 1)[-1]}",
                "wrong language": f"https://github.com/qubit-ltd/rs-redact/blob/{tag}/derive/{wrong_language}",
                "wrong commit": f"https://github.com/qubit-ltd/rs-redact/blob/0000000000000000000000000000000000000000/derive/{expected.rsplit('/', 1)[-1]}",
            }
            for description, invalid in invalid_targets.items():
                with self.subTest(source=source_name, target=description):
                    with tempfile.TemporaryDirectory() as temp:
                        root = Path(temp)
                        self._documentation_fixture(root)
                        source = root / source_name
                        source.write_text(f"[derive]({invalid})\n", encoding="utf-8")
                        with self.assertRaises(CHECKER.CheckError) as raised:
                            CHECKER.assert_published_documentation(root)
                        self.assertIn(source_name, str(raised.exception))
                        self.assertIn(expected, str(raised.exception))
                        self.assertIn(invalid, str(raised.exception))

    def test_published_guides_reject_correct_and_stale_targets_together(self):
        for source_name in ("doc/user_guide.md", "doc/user_guide.zh_CN.md"):
            expected = self._expected_target(source_name)
            for invalid in ("../derive/README.md", "https://github.com/qubit-ltd/rs-redact/blob/main/derive/README.md"):
                with self.subTest(source=source_name, target=invalid):
                    with tempfile.TemporaryDirectory() as temp:
                        root = Path(temp)
                        self._documentation_fixture(root)
                        source = root / source_name
                        source.write_text(f"[derive]({expected})\n[old derive]({invalid})\n", encoding="utf-8")
                        with self.assertRaises(CHECKER.CheckError) as raised:
                            CHECKER.assert_published_documentation(root)
                        self.assertIn(source_name, str(raised.exception))
                        self.assertIn(expected, str(raised.exception))
                        self.assertIn(invalid, str(raised.exception))

    def test_published_documentation_rejects_floating_version(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self._documentation_fixture(root)
            (root / "README.zh_CN.md").write_text(
                "[derive](https://github.com/qubit-ltd/rs-redact/blob/main/derive/README.zh_CN.md)\n",
                encoding="utf-8",
            )
            with self.assertRaises(CHECKER.CheckError) as raised:
                CHECKER.assert_published_documentation(root)
            self.assertIn("README.zh_CN.md", str(raised.exception))
            self.assertIn("main", str(raised.exception))

    def test_published_documentation_rejects_wrong_language_target(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self._documentation_fixture(root)
            (root / "README.zh_CN.md").write_text(
                f"[derive](https://github.com/qubit-ltd/rs-redact/blob/v{CHECKER.RUNTIME_VERSION}/derive/README.md)\n",
                encoding="utf-8",
            )
            with self.assertRaises(CHECKER.CheckError) as raised:
                CHECKER.assert_published_documentation(root)
            self.assertIn("README.zh_CN.md", str(raised.exception))
            self.assertIn("derive/README.zh_CN.md", str(raised.exception))

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
