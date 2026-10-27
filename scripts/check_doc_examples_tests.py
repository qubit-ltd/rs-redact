"""Regression tests for the documentation executable-block contract."""
import importlib.util
import contextlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("check_doc_examples", Path(__file__).with_name("check_doc_examples.py"))
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ExampleContractTests(unittest.TestCase):
    def test_documentation_runs_may_fetch_uncached_dependencies(self):
        self.assertNotIn("--offline", MODULE.cargo_run_command())

    def parse(self, text):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "guide.zh_CN.md"
            path.write_text(text, encoding="utf-8")
            return MODULE.extract(path)

    def test_derive_documents_are_checked(self):
        expected = {
            "README.md", "README.zh_CN.md", "doc/user_guide.md",
            "doc/user_guide.zh_CN.md", "derive/README.md", "derive/README.zh_CN.md",
        }
        self.assertEqual(set(MODULE.DOCUMENTS), expected)
        root = Path(__file__).resolve().parents[1]
        for name in ("derive/README.md", "derive/README.zh_CN.md"):
            examples = MODULE.extract(root / name)
            self.assertTrue(any(item["kind"] == "cargo" for item in examples))
            self.assertGreaterEqual(sum(item["kind"] == "run" for item in examples), 2)

    def test_unannotated_rust_is_rejected_with_location(self):
        with self.assertRaisesRegex(ValueError, r"guide.zh_CN.md:1.*annotation"):
            self.parse("```rust\nfn main() {}\n```\n")

    def test_feature_requirement_and_source_line_survive(self):
        examples = self.parse("# 指南\n\n<!-- redact-example: kind=run features=derive,json -->\n```rust\nfn main() {}\n```\n")
        self.assertEqual(examples[0]["features"], ["derive", "json"])
        self.assertEqual(examples[0]["line"], 5)
        self.assertEqual(examples[0]["code"], "fn main() {}\n")

    def test_http_feature_is_accepted(self):
        examples = self.parse("<!-- redact-example: kind=run features=http -->\n```rust\nfn main() {}\n```\n")
        self.assertEqual(examples[0]["features"], ["http"])

    def test_rust_modifiers_cannot_silently_skip_validation(self):
        with self.assertRaisesRegex(ValueError, "unsupported.*fence"):
            self.parse("```rust,ignore\nfn main() {}\n```\n")

    def test_unknown_features_and_unclosed_blocks_fail(self):
        with self.assertRaisesRegex(ValueError, "unknown feature"):
            self.parse("<!-- redact-example: kind=run features=magic -->\n```rust\nfn main() {}\n```\n")
        with self.assertRaisesRegex(ValueError, "unclosed"):
            self.parse("<!-- redact-example: kind=run features=none -->\n```rust\nfn main() {}\n")

    def test_cargo_annotation_cannot_hide_feature_mismatch(self):
        example = self.parse('<!-- redact-example: kind=cargo features=none -->\n```toml\n[dependencies]\nqubit-redact = { version = "0.8", features = ["json"] }\n```\n')[0]
        with self.assertRaisesRegex(ValueError, "features disagree"):
            MODULE.cargo_dependency(example, "0.8.1")

    def test_cargo_example_version_must_match_current_release(self):
        example = self.parse('<!-- redact-example: kind=cargo features=none -->\n```toml\n[dependencies]\nqubit-redact = "0.7"\n```\n')[0]
        with self.assertRaisesRegex(ValueError, "version"):
            MODULE.cargo_dependency(example, "0.8.1")

    def test_cargo_example_allows_documented_serde_json(self):
        example = self.parse(
            '<!-- redact-example: kind=cargo features=json -->\n'
            '```toml\n[dependencies]\n'
            'qubit-redact = { version = "0.8", features = ["json"] }\n'
            'serde_json = "1"\n```\n'
        )[0]
        MODULE.cargo_dependency(example, "0.8.1")

    def test_cargo_dependency_rejects_checkout_source_conflicts(self):
        example = self.parse(
            '<!-- redact-example: kind=cargo features=json -->\n'
            '```toml\n[dependencies]\n'
            'qubit-redact = { version = "0.8", features = ["json"], git = "https://example.invalid" }\n'
            'serde_json = "1"\n```\n'
        )[0]
        with self.assertRaisesRegex(ValueError, "source conflicts"):
            MODULE.cargo_dependency(example, "0.8.1")

    def test_manifest_preserves_real_dependency_options_and_values(self):
        cargo = {
            "code": '[dependencies]\n'
            'qubit-redact = { version = "0.8", features = ["serde"], default-features = false }\n'
            'serde = { version = "1", features = ["derive", "alloc"], default-features = false }\n'
            'serde_json = "1"\n'
        }
        manifest = MODULE.consumer_manifest(Path("/checkout"), ["serde"], cargo)
        parsed = __import__("tomllib").loads(manifest)["dependencies"]
        self.assertEqual(parsed["qubit-redact"], {
            "version": "0.8", "features": ["serde"], "default-features": False,
            "path": "/checkout",
        })
        self.assertEqual(parsed["serde"], {
            "version": "1", "features": ["derive", "alloc"], "default-features": False,
        })
        self.assertEqual(parsed["serde_json"], "1")

    def test_nearest_matching_cargo_configuration_wins(self):
        examples = [
            {"kind": "cargo", "features": ["serde", "json"], "path": Path("guide.md"), "id": 1},
            {"kind": "run", "features": ["json", "serde"], "path": Path("guide.md")},
            {"kind": "cargo", "features": ["serde"], "path": Path("guide.md"), "id": 2},
            {"kind": "cargo", "features": ["json", "serde"], "path": Path("guide.md"), "id": 3},
            {"kind": "run", "features": ["serde", "json"], "path": Path("guide.md")},
            {"kind": "run", "features": ["serde"], "path": Path("guide.md")},
        ]
        self.assertIs(MODULE.matching_cargo_example(examples, 4), examples[3])
        self.assertIs(MODULE.matching_cargo_example(examples, 5), examples[2])

    def test_cargo_configuration_does_not_cross_document_boundary(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "Cargo.toml").write_text('[package]\nversion = "0.8.1"\n', encoding="utf-8")
            (root / "Cargo.lock").write_text("version = 4\n", encoding="utf-8")
            (root / "README.md").write_text(
                '<!-- redact-example: kind=cargo features=serde -->\n```toml\n'
                '[dependencies]\nqubit-redact = { version = "0.8", features = ["serde"], default-features = false }\n'
                'serde = { version = "1", features = ["derive", "alloc"], default-features = false }\n```\n',
                encoding="utf-8",
            )
            (root / "guide.md").write_text(
                '<!-- redact-example: kind=run features=serde -->\n```rust\nfn main() {}\n```\n',
                encoding="utf-8",
            )
            old_documents = MODULE.DOCUMENTS
            MODULE.DOCUMENTS = ("README.md", "guide.md")
            captured = []

            def fake_runner(command, **kwargs):
                manifest = (Path(kwargs["cwd"]) / "Cargo.toml").read_text(encoding="utf-8")
                captured.append(__import__("tomllib").loads(manifest)["dependencies"])
                return subprocess.CompletedProcess(command, 0, "")

            try:
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    MODULE.run_examples(root, runner=fake_runner)
            finally:
                MODULE.DOCUMENTS = old_documents
            self.assertEqual(len(captured), 2)
            self.assertEqual(captured[0]["serde"]["features"], ["derive", "alloc"])
            self.assertEqual(captured[1]["serde"]["features"], ["derive"])
            self.assertIn("runner fixture", output.getvalue())

    def test_run_examples_passes_matching_document_manifest_to_runner(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "Cargo.toml").write_text('[package]\nversion = "0.8.1"\n', encoding="utf-8")
            (root / "Cargo.lock").write_text("version = 4\n", encoding="utf-8")
            docs = ["guide.md"]
            (root / docs[0]).write_text(
                '<!-- redact-example: kind=cargo features=serde,json -->\n```toml\n'
                '[dependencies]\nqubit-redact = { version = "0.8", features = ["json", "serde"], default-features = false }\n'
                'serde = { version = "1", features = ["derive"], default-features = false }\n```\n'
                '<!-- redact-example: kind=run features=json,serde -->\n```rust\nfn main() {}\n```\n',
                encoding="utf-8",
            )
            old_documents = MODULE.DOCUMENTS
            MODULE.DOCUMENTS = tuple(docs)
            captured = []

            def fake_runner(command, **kwargs):
                manifest = (Path(kwargs["cwd"]) / "Cargo.toml").read_text(encoding="utf-8")
                captured.append(__import__("tomllib").loads(manifest)["dependencies"])
                return subprocess.CompletedProcess(command, 0, "")

            try:
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    MODULE.run_examples(root, runner=fake_runner)
            finally:
                MODULE.DOCUMENTS = old_documents
            self.assertEqual(len(captured), 2)
            self.assertFalse(captured[1]["qubit-redact"]["default-features"])
            self.assertEqual(captured[1]["serde"], {
                "version": "1", "features": ["derive"], "default-features": False,
            })
            self.assertIn("document config", output.getvalue())

    def test_unmatched_run_uses_explicit_runner_fixture(self):
        manifest = MODULE.consumer_manifest(Path("/checkout"), ["serde"])
        dependencies = __import__("tomllib").loads(manifest)["dependencies"]
        self.assertEqual(dependencies["serde"]["features"], ["derive"])

    def test_matching_config_does_not_invent_missing_direct_dependency(self):
        cargo = {"code": '[dependencies]\nqubit-redact = { version = "0.8", features = ["serde"] }\n'}
        dependencies = __import__("tomllib").loads(
            MODULE.consumer_manifest(Path("/checkout"), ["serde"], cargo)
        )["dependencies"]
        self.assertNotIn("serde", dependencies)

    def test_invalid_dependency_feature_shape_has_document_location(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "Cargo.toml").write_text('[package]\nversion = "0.8.1"\n', encoding="utf-8")
            (root / "Cargo.lock").write_text("version = 4\n", encoding="utf-8")
            (root / "guide.md").write_text(
                '<!-- redact-example: kind=cargo features=none -->\n```toml\n'
                '[dependencies]\nqubit-redact = { version = "0.8", features = 1 }\n```\n',
                encoding="utf-8",
            )
            old_documents = MODULE.DOCUMENTS
            MODULE.DOCUMENTS = ("guide.md",)
            try:
                with self.assertRaisesRegex(
                    ValueError, r"(?s)guide\.md:3: documentation example failed.*features.*array"
                ):
                    MODULE.run_examples(root, runner=lambda *_args, **_kwargs: self.fail("runner must not run"))
            finally:
                MODULE.DOCUMENTS = old_documents

    def test_invalid_dependencies_table_has_document_location(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "Cargo.toml").write_text('[package]\nversion = "0.8.1"\n', encoding="utf-8")
            (root / "Cargo.lock").write_text("version = 4\n", encoding="utf-8")
            (root / "guide.md").write_text(
                '<!-- redact-example: kind=cargo features=none -->\n```toml\n'
                'dependencies = []\n```\n',
                encoding="utf-8",
            )
            old_documents = MODULE.DOCUMENTS
            MODULE.DOCUMENTS = ("guide.md",)
            try:
                with self.assertRaisesRegex(
                    ValueError, r"(?s)guide\.md:3: documentation example failed.*dependencies.*table"
                ):
                    MODULE.run_examples(root, runner=lambda *_args, **_kwargs: self.fail("runner must not run"))
            finally:
                MODULE.DOCUMENTS = old_documents

    def test_cargo_example_feature_failure_keeps_document_location(self):
        """The real resolver must reject a feature absent from the checkout crate."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = Path(__file__).resolve().parents[1]
            package = __import__("tomllib").loads((repo / "Cargo.toml").read_text(encoding="utf-8"))
            (root / "Cargo.toml").write_text((repo / "Cargo.toml").read_text(encoding="utf-8"), encoding="utf-8")
            (root / "Cargo.lock").write_text((repo / "Cargo.lock").read_text(encoding="utf-8"), encoding="utf-8")
            (root / "guide.md").write_text(
                '<!-- redact-example: kind=cargo features=serde -->\n```toml\n'
                '[dependencies]\nqubit-redact = { version = "' + package["package"]["version"] + '", features = ["serde"] }\n'
                'serde = { version = "1", features = ["no-such-feature-rs-redact-fixture"] }\n```\n'
                '<!-- redact-example: kind=run features=serde -->\n```rust\nfn main() {}\n```\n',
                encoding="utf-8",
            )
            old_documents = MODULE.DOCUMENTS
            MODULE.DOCUMENTS = ("guide.md",)
            try:
                def real_checkout_runner(command, **kwargs):
                    manifest_path = Path(kwargs["cwd"]) / "Cargo.toml"
                    manifest = manifest_path.read_text(encoding="utf-8")
                    manifest_path.write_text(
                        manifest.replace(json.dumps(str(root)), json.dumps(str(repo))),
                        encoding="utf-8",
                    )
                    return subprocess.run(
                        command, cwd=kwargs["cwd"], env=kwargs["env"], text=True,
                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                        timeout=kwargs["timeout"],
                    )

                with self.assertRaisesRegex(
                    ValueError, r"guide\.md:3: documentation example failed"
                ) as captured:
                    MODULE.run_examples(root, runner=real_checkout_runner)
            finally:
                MODULE.DOCUMENTS = old_documents
            message = str(captured.exception)
            self.assertIn("no-such-feature-rs-redact-fixture", message)
            self.assertNotIn("failed to get `serde`", message)


if __name__ == "__main__":
    unittest.main()
