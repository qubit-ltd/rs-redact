"""Regression tests for Cargo feature-matrix validation."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
CHECKER = ROOT / "scripts" / "check_feature_matrix.py"
ENV = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}


def run_checker(manifest, matrix):
    return subprocess.run(
        [sys.executable, str(CHECKER), "--manifest", str(manifest), "--matrix", str(matrix)],
        capture_output=True, text=True, check=False, env=ENV,
    )


def fixture(checks, manifest_text=None):
    directory = tempfile.TemporaryDirectory()
    root = Path(directory.name)
    manifest = root / "Cargo.toml"
    matrix = root / "matrix.json"
    manifest.write_text(manifest_text or (
        '[package]\nname = "fixture"\nversion = "0.1.0"\n'
        '[features]\ndefault = ["base"]\nbase = []\nextra = ["base", "serde?/derive"]\n'
        '[dependencies]\nserde = { version = "1", optional = true }\n'), encoding="utf-8")
    matrix.write_text(json.dumps({"version": 1, "checks": checks}), encoding="utf-8")
    return directory, manifest, matrix


def project_matrix():
    return json.loads((ROOT / ".infra/ci/cargo-matrix.json").read_text(encoding="utf-8"))


class FeatureMatrixTests(unittest.TestCase):
    def test_repository_matrix_is_structurally_valid(self):
        result = subprocess.run([sys.executable, str(CHECKER)], capture_output=True,
                                text=True, check=False, env=ENV)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "feature-matrix: valid")

    def test_rejects_empty_matrix_and_names_the_runner_cannot_execute(self):
        directory, manifest, matrix = fixture([])
        try:
            result = run_checker(manifest, matrix)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("matrix checks must not be empty", result.stderr)
            matrix.write_text(json.dumps({"version": 1, "checks": [
                {"name": "bad/name", "commands": ["test"], "packages": ["fixture"]},
            ]}), encoding="utf-8")
            result = run_checker(manifest, matrix)
        finally:
            directory.cleanup()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("name contains characters unsupported by the matrix runner", result.stderr)

    def test_does_not_judge_which_feature_combinations_are_reasonable(self):
        matrix = project_matrix()
        matrix["checks"] = [entry for entry in matrix["checks"] if entry["name"] != "http-uri"]
        matrix["checks"].append({"name": "additional-combination", "commands": ["test"],
                                 "packages": ["qubit-redact"], "defaultFeatures": False,
                                 "features": ["derive", "uri"]})
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "matrix.json"
            path.write_text(json.dumps(matrix), encoding="utf-8")
            result = run_checker(ROOT / "Cargo.toml", path)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_rejects_manifest_feature_references_that_do_not_exist(self):
        matrix = project_matrix()
        entry = next(item for item in matrix["checks"] if item["name"] == "http-uri")
        entry["features"] = ["missing-feature"]
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "matrix.json"
            path.write_text(json.dumps(matrix), encoding="utf-8")
            result = run_checker(ROOT / "Cargo.toml", path)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unknown feature 'missing-feature'", result.stderr)

    def test_external_dependency_feature_selector_is_validated_without_curating_it(self):
        checks = [{"name": "dependency-feature", "commands": ["test"],
                   "packages": ["fixture"], "defaultFeatures": False,
                   "features": ["serde/arbitrary_precision"]}]
        directory, manifest, matrix = fixture(checks)
        try:
            result = run_checker(manifest, matrix)
        finally:
            directory.cleanup()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_fixture_feature_alias_closure_and_weak_dependency_feature_are_accepted(self):
        checks = [{"name": "focused", "commands": ["test"], "packages": ["fixture"],
                   "defaultFeatures": False, "features": ["extra"]}]
        directory, manifest, matrix = fixture(checks)
        try:
            result = run_checker(manifest, matrix)
        finally:
            directory.cleanup()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_rejects_weak_reference_to_non_optional_dependency(self):
        manifest = ('[package]\nname = "fixture"\nversion = "0.1.0"\n'
                    '[features]\ndefault = []\nbase = ["serde?/derive"]\n'
                    '[dependencies]\nserde = { version = "1" }\n')
        checks = [{"name": "bad-weak", "commands": ["test"], "packages": ["fixture"],
                   "defaultFeatures": False, "features": ["base"]}]
        directory, manifest_path, matrix_path = fixture(checks, manifest)
        try:
            result = run_checker(manifest_path, matrix_path)
        finally:
            directory.cleanup()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("weak feature reference for non-optional dependency 'serde'", result.stderr)

    def test_rejects_invalid_reference_in_unselected_manifest_feature(self):
        manifest = ('[package]\nname = "fixture"\nversion = "0.1.0"\n'
                    '[features]\ndefault = []\nbase = []\nunused = ["missing-feature"]\n'
                    '[dependencies]\n')
        checks = [{"name": "base-only", "commands": ["test"], "packages": ["fixture"],
                   "defaultFeatures": False, "features": ["base"]}]
        directory, manifest_path, matrix_path = fixture(checks, manifest)
        try:
            result = run_checker(manifest_path, matrix_path)
        finally:
            directory.cleanup()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("manifest feature 'unused' references unknown feature 'missing-feature'",
                      result.stderr)

    def test_rejects_invalid_default_reference_when_matrix_disables_defaults(self):
        manifest = ('[package]\nname = "fixture"\nversion = "0.1.0"\n'
                    '[features]\ndefault = ["missing-feature"]\nbase = []\n'
                    '[dependencies]\n')
        checks = [{"name": "base-only", "commands": ["test"], "packages": ["fixture"],
                   "defaultFeatures": False, "features": ["base"]}]
        directory, manifest_path, matrix_path = fixture(checks, manifest)
        try:
            result = run_checker(manifest_path, matrix_path)
        finally:
            directory.cleanup()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("manifest default: manifest feature '__matrix_default__' references unknown feature",
                      result.stderr)

    def test_rejects_malformed_external_dependency_feature_selectors(self):
        for selector in ("serde//derive", "serde?/derive", "serde/derive?"):
            with self.subTest(selector=selector):
                checks = [{"name": "bad-external", "commands": ["test"],
                           "packages": ["fixture"], "defaultFeatures": False,
                           "features": [selector]}]
                directory, manifest, matrix = fixture(checks)
                try:
                    result = run_checker(manifest, matrix)
                finally:
                    directory.cleanup()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("unknown dependency feature", result.stderr)

    def test_rejects_unknown_features_duplicate_names_and_invalid_types(self):
        checks = [
            {"name": "same", "commands": ["check"], "packages": ["fixture"],
             "defaultFeatures": False, "features": ["unknown"]},
            {"name": "same", "commands": "test", "packages": "fixture",
             "defaultFeatures": "false", "features": ["base", "base"]},
        ]
        directory, manifest, matrix = fixture(checks)
        try:
            result = run_checker(manifest, matrix)
        finally:
            directory.cleanup()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("duplicate check name", result.stderr)
        self.assertIn("unknown feature", result.stderr)
        self.assertIn("commands must be a non-empty array", result.stderr)

    def test_invalid_json_and_toml_report_context(self):
        directory, manifest, matrix = fixture([])
        try:
            matrix.write_text('{"version": 1,', encoding="utf-8")
            result = run_checker(manifest, matrix)
            self.assertIn("feature-matrix: matrix:", result.stderr)
            manifest.write_text("[package\n", encoding="utf-8")
            result = run_checker(manifest, matrix)
            self.assertIn("feature-matrix: manifest:", result.stderr)
        finally:
            directory.cleanup()


if __name__ == "__main__":
    unittest.main()
