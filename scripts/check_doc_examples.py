#!/usr/bin/env python3
"""Execute annotated Rust and Cargo examples from both README/guide languages.

Each Rust block is a complete binary. Cargo blocks are dependency snippets and
are checked with an empty binary. An immediately preceding annotation declares
kind=run|cargo and a declared feature set. Undeclared blocks fail closed.
Examples run from a fresh temporary directory, using this checkout via a path
dependency. Rust blocks use the nearest preceding Cargo configuration in the same
document when its feature annotation matches; otherwise they use explicit runner
fixtures for serde, serde_json, and http as required by the annotated features.
"""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib

ANNOTATION = re.compile(r"<!-- redact-example: kind=(run|cargo) features=([a-z,]+) -->")
DOCUMENTS = ("README.md", "README.zh_CN.md", "doc/user_guide.md", "doc/user_guide.zh_CN.md", "derive/README.md", "derive/README.zh_CN.md")
VALID_FEATURES = frozenset({"derive", "serde", "bigdecimal", "json", "http", "uri"})


def extract(path):
    """Return executable blocks with their original source locations."""
    lines = path.read_text(encoding="utf-8").splitlines()
    result = []
    index = 0
    while index < len(lines):
        language = lines[index].strip().removeprefix("```")
        if lines[index].strip().startswith("```") and language.startswith(("rust", "toml")) and language not in ("rust", "toml"):
            raise ValueError(f"{path}:{index + 1}: unsupported executable fence modifier")
        if not lines[index].strip().startswith("```") or language not in ("rust", "toml"):
            index += 1
            continue
        start = index
        annotation = ANNOTATION.fullmatch(lines[index - 1].strip()) if index else None
        if annotation is None:
            raise ValueError(f"{path}:{start + 1}: missing executable example annotation")
        kind, feature_text = annotation.groups()
        if (language == "rust") != (kind == "run"):
            raise ValueError(f"{path}:{start + 1}: example kind disagrees with fence language")
        features = [] if feature_text == "none" else feature_text.split(",")
        if any(feature not in VALID_FEATURES for feature in features) or len(set(features)) != len(features):
            raise ValueError(f"{path}:{start + 1}: unknown feature or repeated feature")
        index += 1
        body = []
        while index < len(lines) and lines[index].strip() != "```":
            body.append(lines[index])
            index += 1
        if index == len(lines):
            raise ValueError(f"{path}:{start + 1}: unclosed code block")
        result.append(dict(path=path, line=start + 2, kind=kind, features=features, code="\n".join(body) + "\n"))
        index += 1
    return result


def allowed_extra_dependencies(features):
    """Return optional dependency names permitted in documented Cargo snippets."""
    allowed = set()
    if set(features) & {"derive", "serde", "json", "http", "bigdecimal"}:
        allowed.add("serde")
    if set(features) & {"json", "http"}:
        allowed.add("serde_json")
    if "http" in features:
        allowed.add("http")
    return allowed


def cargo_dependency(example, version):
    """Validate the advertised dependency, including its declared feature set."""
    data = tomllib.loads(example["code"])
    dependencies = data.get("dependencies", {})
    if not isinstance(dependencies, dict):
        raise ValueError("Cargo example dependencies must be a table")
    dependency = dependencies.get("qubit-redact")
    if isinstance(dependency, str):
        dependency = {"version": dependency}
    if not isinstance(dependency, dict):
        raise ValueError("Cargo example requires [dependencies].qubit-redact")
    expected = {version, ".".join(version.split(".")[:2])}
    if dependency.get("version") not in expected:
        raise ValueError(f"Cargo example version must describe {version}")
    features = dependency.get("features", [])
    if not isinstance(features, list) or any(not isinstance(feature, str) for feature in features):
        raise ValueError("Cargo example dependency features must be an array of strings")
    if set(features) != set(example["features"]):
        raise ValueError("Cargo example features disagree with annotation")
    conflicts = set(dependency) & {"path", "git", "branch", "tag", "rev", "registry"}
    if conflicts:
        raise ValueError(f"qubit-redact source conflicts with checkout path: {sorted(conflicts)}")
    extra = set(dependencies) - {"qubit-redact"}
    unexpected = extra - allowed_extra_dependencies(example["features"])
    if unexpected:
        raise ValueError(f"Cargo example contains unexpected dependencies: {sorted(unexpected)}")
    if set(data) != {"dependencies"}:
        raise ValueError("Cargo example must contain only [dependencies]")
    return dependency


def consumer_manifest(root, features, cargo_example=None):
    """Build a consumer manifest from the documented dependencies or runner fixtures."""
    if cargo_example is None:
        dependencies = tomllib.loads("[dependencies]\n" + consumer_dependencies(features))["dependencies"]
        runtime = {"path": str(root), "default-features": False, "features": list(features)}
    else:
        dependencies = tomllib.loads(cargo_example["code"])["dependencies"]
        runtime = dependencies["qubit-redact"]
        runtime = {"version": runtime} if isinstance(runtime, str) else dict(runtime)
        runtime["path"] = str(root)
        dependencies = dict(dependencies)
    dependencies["qubit-redact"] = runtime
    return (
        '[package]\nname = "redact-doc-example"\nversion = "0.0.0"\nedition = "2024"\n'
        '[dependencies]\n' + "".join(
            f"{toml_key(name)} = {toml_value(value)}\n"
            for name, value in dependencies.items()
        )
    )


def toml_key(value):
    """Serialize a basic or quoted TOML key."""
    if re.fullmatch(r"[A-Za-z0-9_-]+", value):
        return value
    return json.dumps(value, ensure_ascii=False)


def toml_value(value):
    """Serialize the TOML value types supported by Cargo dependency tables."""
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return repr(value)
    if isinstance(value, list):
        return "[" + ", ".join(toml_value(item) for item in value) + "]"
    if isinstance(value, dict):
        return "{ " + ", ".join(
            f"{toml_key(key)} = {toml_value(item)}" for key, item in value.items()
        ) + " }"
    raise ValueError(f"unsupported TOML dependency value: {type(value).__name__}")


def matching_cargo_example(examples, index):
    """Find the nearest preceding matching Cargo snippet in the same document."""
    current = examples[index]
    for candidate in reversed(examples[:index]):
        if (
            candidate["path"] == current["path"]
            and candidate["kind"] == "cargo"
            and set(candidate["features"]) == set(current["features"])
        ):
            return candidate
    return None


def consumer_dependencies(features):
    """Return extra dependencies required to compile annotated run examples."""
    manifest = ""
    if set(features) & {"derive", "serde", "json", "http", "bigdecimal"}:
        manifest += 'serde = { version = "1", features = ["derive"] }\n'
    if set(features) & {"json", "http"}:
        manifest += 'serde_json = "1"\n'
    if "http" in features:
        manifest += 'http = "1"\n'
    return manifest


def run_examples(root, runner=None):
    """Compile and run every language variant without relying on repository cwd."""
    if shutil.which("cargo") is None:
        raise ValueError("cargo is required to verify documentation examples")
    package = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))
    examples = [example for name in DOCUMENTS for example in extract(root / name)]
    if not examples:
        raise ValueError("no executable documentation examples found")
    with tempfile.TemporaryDirectory(prefix="rs-redact-doc-examples-") as directory:
        workspace = Path(directory)
        validated_cargo = {}
        for ordinal, example in enumerate(examples):
            location = f'{example["path"].relative_to(root)}:{example["line"]}'
            try:
                if example["kind"] == "cargo":
                    cargo_dependency(example, package["package"]["version"])
                    validated_cargo[id(example)] = example
                consumer = workspace / f"example-{ordinal}"
                (consumer / "src").mkdir(parents=True)
                cargo_example = (
                    example if example["kind"] == "cargo"
                    else matching_cargo_example(examples, ordinal)
                )
                if cargo_example is not None and id(cargo_example) not in validated_cargo:
                    cargo_example = None
                manifest = consumer_manifest(root, example["features"], cargo_example)
                (consumer / "Cargo.toml").write_text(manifest, encoding="utf-8")
                shutil.copyfile(root / "Cargo.lock", consumer / "Cargo.lock")
                code = example["code"] if example["kind"] == "run" else "fn main() {}\n"
                (consumer / "src/main.rs").write_text(code, encoding="utf-8")
                env = os.environ.copy()
                env["CARGO_TARGET_DIR"] = str(workspace / "target")
                invoke = runner or subprocess.run
                completed = invoke(
                    cargo_run_command(), cwd=consumer, env=env,
                    text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120,
                )
                if completed.returncode:
                    raise ValueError(completed.stdout)
            except (ValueError, subprocess.TimeoutExpired) as error:
                raise ValueError(f"{location}: documentation example failed\n{error}") from error
            source = (
                "document config"
                if example["kind"] == "cargo" or cargo_example
                else "runner fixture"
            )
            print(f"PASS {location} ({example['kind']}, features={example['features']}, {source})", flush=True)
    print(f"Verified {len(examples)} documentation examples in both languages.")


def cargo_run_command():
    """Build examples with the registry available when dependencies are uncached."""
    return ["cargo", "run", "--quiet"]


def main():
    """Use this script's checkout, independent of the caller's working directory."""
    try:
        run_examples(Path(__file__).resolve().parents[1])
    except (ValueError, OSError) as error:
        print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
