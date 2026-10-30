"""Unit tests for package-checker anti-bypass behavior."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

SCRIPT = Path(__file__).with_name("check_packaged_derive.py")
SPEC = importlib.util.spec_from_file_location("check_packaged_derive", SCRIPT)
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


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


if __name__ == "__main__":
    unittest.main()
