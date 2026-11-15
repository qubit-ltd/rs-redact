"""Build and exercise the normalized crates that this workspace would publish."""
from __future__ import annotations

import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tarfile
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parent.parent


def package_version(manifest: Path) -> str:
    return tomllib.loads(manifest.read_text(encoding="utf-8"))["package"]["version"]


RUNTIME_VERSION = package_version(ROOT / "Cargo.toml")
DERIVE_VERSION = package_version(ROOT / "derive/Cargo.toml")
DERIVE_DOC_TAG = f"v{RUNTIME_VERSION.rsplit('.', 1)[0]}"
MARKDOWN_LINK = re.compile(r"(?<!!)\[[^\]]*\]\(([^)\s]+)(?:\s+[^)]*)?\)")


class CheckError(RuntimeError):
    pass


def require_positive_test_summary(output: str) -> None:
    pattern = re.compile(
        r"test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; "
        r"\d+ ignored; \d+ measured; \d+ filtered out"
        r"(?:; finished in [^\r\n]+)?"
    )
    summaries = [match for line in output.splitlines()
                 if (match := pattern.fullmatch(line)) is not None]
    if len(summaries) != 1:
        raise CheckError("expected exactly one recognizable libtest summary")
    status, passed, failed = summaries[0].groups()
    if status != "ok" or int(failed) != 0:
        raise CheckError("recursive projection tests did not pass")
    if int(passed) == 0:
        raise CheckError("recursive projection test target executed zero tests")


def run(args: list[str], *, cwd: Path, env: dict[str, str] | None = None) -> str:
    result = subprocess.run(args, cwd=cwd, env=env, text=True, capture_output=True, check=False)
    if result.returncode:
        raise CheckError(f"command failed ({result.returncode}): {args!r}\n{result.stdout}{result.stderr}")
    return result.stdout


def safe_extract(archive: Path, destination: Path) -> None:
    root = destination.resolve()
    with tarfile.open(archive, "r:gz") as bundle:
        for member in bundle.getmembers():
            path = PurePosixPath(member.name)
            if (path.is_absolute() or ".." in path.parts or member.issym() or member.islnk()
                    or not (member.isfile() or member.isdir())):
                raise CheckError(f"unsafe archive member: {member.name}")
            target = (destination / Path(*path.parts)).resolve()
            if target != root and root not in target.parents:
                raise CheckError(f"archive member escapes destination: {member.name}")
        bundle.extractall(destination)


def package_manifest(path: Path, name: str, version: str) -> Path:
    manifest = path / "Cargo.toml"
    data = tomllib.loads(manifest.read_text(encoding="utf-8"))
    package = data.get("package", {})
    if package.get("name") != name or package.get("version") != version:
        raise CheckError(f"unexpected normalized package manifest: {manifest}")
    if any("path" in dependency for _, dependency in iter_dependency_tables(data)):
        raise CheckError(f"published manifest retains a path dependency: {manifest}")
    return manifest


def iter_dependency_tables(value: object, *, include_dev: bool = True):
    if isinstance(value, dict):
        sections = ("dependencies", "build-dependencies", "dev-dependencies") if include_dev else ("dependencies", "build-dependencies")
        for section in sections:
            dependencies = value.get(section)
            if isinstance(dependencies, dict):
                for name, dependency in dependencies.items():
                    if isinstance(dependency, dict):
                        yield name, dependency
        for child in value.values():
            yield from iter_dependency_tables(child, include_dev=include_dev)


def assert_manifest_location(actual: Path, expected_package_dir: Path) -> None:
    actual = actual.resolve()
    expected = (expected_package_dir / "Cargo.toml").resolve()
    if actual != expected or not expected_package_dir.resolve().is_dir():
        raise CheckError(f"package resolved outside extracted archive: {actual}")


def assert_derive_requirement(runtime_manifest: Path) -> None:
    manifest = tomllib.loads(runtime_manifest.read_text(encoding="utf-8"))
    requirement = manifest.get("dependencies", {}).get("qubit-redact-derive")
    if isinstance(requirement, dict):
        requirement = requirement.get("version")
    minor_version = DERIVE_VERSION.rsplit(".", 1)[0]
    if requirement not in (minor_version, f"^{minor_version}"):
        raise CheckError(f"runtime derive requirement must target minor version {minor_version}: {requirement!r}")


def assert_derive_has_no_runtime_release_dependency(derive_manifest: Path) -> None:
    manifest = tomllib.loads(derive_manifest.read_text(encoding="utf-8"))
    for name, dependency in iter_dependency_tables(manifest, include_dev=False):
        if name == "qubit-redact" or dependency.get("package") == "qubit-redact":
            raise CheckError("derive archive has a runtime dependency cycle")


def assert_published_documentation(package_root: Path) -> None:
    """Require both READMEs and both user guides to link to release derive docs."""
    expected = {
        "README.md": f"https://github.com/qubit-ltd/rs-redact/blob/{DERIVE_DOC_TAG}/derive/README.md",
        "README.zh_CN.md": f"https://github.com/qubit-ltd/rs-redact/blob/{DERIVE_DOC_TAG}/derive/README.zh_CN.md",
        "doc/user_guide.md": f"https://github.com/qubit-ltd/rs-redact/blob/{DERIVE_DOC_TAG}/derive/README.md",
        "doc/user_guide.zh_CN.md": f"https://github.com/qubit-ltd/rs-redact/blob/{DERIVE_DOC_TAG}/derive/README.zh_CN.md",
    }
    for source_name, target in expected.items():
        source = package_root / source_name
        if not source.is_file():
            raise CheckError(f"{source_name}: missing source document for derive target {target}")
        links = MARKDOWN_LINK.findall(source.read_text(encoding="utf-8"))
        candidates = [link for link in links if "derive/README" in link]
        if target not in candidates or any(link != target for link in candidates):
            raise CheckError(
                f"{source_name}: expected pinned derive target {target}; found {candidates!r}"
            )


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="redact-package-") as temp:
        temp_root = Path(temp).resolve()
        target = temp_root / "target"
        env = os.environ.copy()
        env["CARGO_TARGET_DIR"] = str(target)
        package_args = ["cargo", "package", "--workspace", "--no-verify", "--allow-dirty", "--target-dir", str(target)]
        print(f"PACKAGING: {package_args!r}", flush=True)
        run(package_args, cwd=ROOT, env=env)
        archive_dir = target / "package"
        runtime_archive = archive_dir / f"qubit-redact-{RUNTIME_VERSION}.crate"
        derive_archive = archive_dir / f"qubit-redact-derive-{DERIVE_VERSION}.crate"
        if not runtime_archive.is_file() or not derive_archive.is_file():
            raise CheckError(f"expected package archives missing in {archive_dir}")
        extracted = temp_root / "extracted"
        extracted.mkdir()
        safe_extract(runtime_archive, extracted)
        safe_extract(derive_archive, extracted)
        runtime_dir = extracted / f"qubit-redact-{RUNTIME_VERSION}"
        derive_dir = extracted / f"qubit-redact-derive-{DERIVE_VERSION}"
        package_manifest(runtime_dir, "qubit-redact", RUNTIME_VERSION)
        package_manifest(derive_dir, "qubit-redact-derive", DERIVE_VERSION)
        assert_published_documentation(runtime_dir)
        assert_derive_requirement(runtime_dir / "Cargo.toml")
        assert_derive_has_no_runtime_release_dependency(derive_dir / "Cargo.toml")
        if not (derive_dir / "src/serde/recursive_projection.rs").is_file():
            raise CheckError("derive archive is missing recursive projection implementation")
        print(f"ARCHIVES: {runtime_archive}, {derive_archive}", flush=True)

        consumer = temp_root / "consumer"
        (consumer / "src").mkdir(parents=True)
        (consumer / "tests").mkdir()
        (consumer / "src/main.rs").write_text("fn main() {}\n", encoding="utf-8")
        (consumer / "Cargo.toml").write_text(
            f'''[package]
name = "redact-package-regression"
version = "0.0.0"
edition = "2024"
publish = false

[workspace]

[features]
derive = ["qubit-redact/derive"]
serde = ["qubit-redact/serde"]
json = ["qubit-redact/json"]

[dependencies]
qubit-redact = {{ version = "={RUNTIME_VERSION}" }}
qubit-redact-derive = "={DERIVE_VERSION}"
serde = {{ version = "1", features = ["derive"] }}
serde_json = "1"

[patch.crates-io]
qubit-redact = {{ path = "{runtime_dir}" }}
qubit-redact-derive = {{ path = "{derive_dir}" }}
''', encoding="utf-8"
        )
        metadata = json.loads(run(["cargo", "metadata", "--format-version", "1", "--all-features"], cwd=consumer, env=env))
        for name, expected in (("qubit-redact", runtime_dir), ("qubit-redact-derive", derive_dir)):
            package = next(p for p in metadata["packages"] if p["name"] == name)
            actual = Path(package["manifest_path"]).resolve()
            assert_manifest_location(actual, expected)
            if temp_root not in actual.parents:
                raise CheckError(f"{name} resolved outside this temporary archive root: {actual}")
        run(["cargo", "generate-lockfile"], cwd=consumer, env=env)
        skip = ROOT / "tests/fixtures/pass/generic_skip_bounds.rs"
        keyed = ROOT / "tests/fixtures/pass/generic_keyed_by.rs"
        projection = ROOT / "tests/derive_recursive_projection_tests.rs"
        shutil.copy2(skip, consumer / "src/main.rs")
        run(["cargo", "run", "--locked", "--no-default-features"], cwd=consumer, env=env)
        shutil.copy2(keyed, consumer / "src/main.rs")
        run(["cargo", "run", "--locked", "--features", "derive,serde,json"], cwd=consumer, env=env)
        shutil.copy2(projection, consumer / "tests/derive_recursive_projection_tests.rs")
        result = run(["cargo", "test", "--locked", "--test", "derive_recursive_projection_tests", "--features", "derive,serde,json", "--", "--nocapture"], cwd=consumer, env=env)
        require_positive_test_summary(result)
        print("PASS: normalized workspace archives compiled and passed skip/keyed_by/recursive projection regressions (archive patch, not registry verification)")


if __name__ == "__main__":
    try:
        main()
    except (CheckError, OSError, tarfile.TarError, StopIteration) as error:
        raise SystemExit(f"packaged derive check failed: {error}")
