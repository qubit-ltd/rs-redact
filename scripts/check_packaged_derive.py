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
RUNTIME_VERSION = "0.10.0"
DERIVE_VERSION = "0.9.0"


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
    if requirement not in (DERIVE_VERSION, f"^{DERIVE_VERSION}"):
        raise CheckError(f"runtime derive lower bound is not 0.9.0: {requirement!r}")


def assert_derive_has_no_runtime_release_dependency(derive_manifest: Path) -> None:
    manifest = tomllib.loads(derive_manifest.read_text(encoding="utf-8"))
    for name, dependency in iter_dependency_tables(manifest, include_dev=False):
        if name == "qubit-redact" or dependency.get("package") == "qubit-redact":
            raise CheckError("derive archive has a runtime dependency cycle")


def local_qubit_json_source() -> Path | None:
    candidate = ROOT.parent / "rs-json"
    if not (candidate / "Cargo.toml").is_file():
        result = subprocess.run(
            ["git", "rev-parse", "--git-common-dir"], cwd=ROOT,
            text=True, capture_output=True, check=False,
        )
        if result.returncode == 0:
            common_dir = Path(result.stdout.strip())
            if not common_dir.is_absolute():
                common_dir = ROOT / common_dir
            candidate = common_dir.resolve().parent.parent / "rs-json"
    if not (candidate / "Cargo.toml").is_file():
        return None
    return candidate.resolve()


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="redact-package-") as temp:
        temp_root = Path(temp).resolve()
        target = temp_root / "target"
        env = os.environ.copy()
        env["CARGO_TARGET_DIR"] = str(target)
        package_args = ["cargo", "package", "--workspace", "--no-verify", "--allow-dirty", "--target-dir", str(target)]
        local_json = local_qubit_json_source()
        json_manifest = local_json / "Cargo.toml" if local_json is not None else None
        json_version = None
        if json_manifest is not None and json_manifest.is_file():
            json_version = tomllib.loads(json_manifest.read_text(encoding="utf-8")).get("package", {}).get("version")
        if json_version == "0.12.0":
            # crates.io currently has no qubit-json 0.12.0. This temporary
            # source lets Cargo package the root archive without changing its
            # normalized registry dependency or the root/derive archive checks.
            package_args = ["cargo", "--config", f'patch.crates-io.qubit-json.path="{json_manifest.parent.resolve()}"', *package_args[1:]]
            print("ENVIRONMENT ADAPTATION: crates.io lacks qubit-json 0.12.0; this single temporary source does not replace either target archive.", flush=True)
        print(f"PACKAGING: {package_args!r}", flush=True)
        workspace_json = ROOT.parent / "rs-json"
        created_workspace_link = False
        if json_version == "0.12.0" and not workspace_json.exists() and not workspace_json.is_symlink():
            workspace_json.symlink_to(local_json, target_is_directory=True)
            created_workspace_link = True
        try:
            run(package_args, cwd=ROOT, env=env)
        finally:
            if (created_workspace_link and workspace_json.is_symlink()
                    and workspace_json.resolve() == local_json.resolve()):
                workspace_json.unlink()
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
        assert_derive_requirement(runtime_dir / "Cargo.toml")
        assert_derive_has_no_runtime_release_dependency(derive_dir / "Cargo.toml")
        if not (derive_dir / "src/serde/recursive_projection.rs").is_file():
            raise CheckError("derive archive is missing recursive projection implementation")
        print(f"ARCHIVES: {runtime_archive}, {derive_archive}", flush=True)

        consumer = temp_root / "consumer"
        (consumer / "src").mkdir(parents=True)
        (consumer / "tests").mkdir()
        (consumer / "src/main.rs").write_text("fn main() {}\n", encoding="utf-8")
        json_consumer_patch = f'qubit-json = {{ path = "{local_json.resolve()}" }}\n' if json_version == "0.12.0" else ""
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
{json_consumer_patch}''', encoding="utf-8"
        )
        metadata = json.loads(run(["cargo", "metadata", "--format-version", "1", "--all-features"], cwd=consumer, env=env))
        for name, expected in (("qubit-redact", runtime_dir), ("qubit-redact-derive", derive_dir)):
            package = next(p for p in metadata["packages"] if p["name"] == name)
            actual = Path(package["manifest_path"]).resolve()
            assert_manifest_location(actual, expected)
            if temp_root not in actual.parents:
                raise CheckError(f"{name} resolved outside this temporary archive root: {actual}")
        if json_version == "0.12.0":
            package = next(p for p in metadata["packages"] if p["name"] == "qubit-json")
            assert_manifest_location(Path(package["manifest_path"]), local_json)
            print(f"DEPENDENCY SOURCE: qubit-json 0.12.0 from {local_json.resolve()} (temporary registry substitute)", flush=True)
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
