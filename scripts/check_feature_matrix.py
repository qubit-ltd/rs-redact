#!/usr/bin/env python3
"""Validate Cargo feature-matrix structure and references against its manifest."""
import argparse
import json
from pathlib import Path
import re
import sys
import tomllib

COMMANDS = {"check", "build", "test", "doc", "doc-test", "clippy"}
ENTRY_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.+-]*$")
CHECK_FIELDS = {"name", "commands", "packages", "defaultFeatures", "allFeatures", "features"}


def fail(message):
    raise ValueError(message)


def read_manifest(path):
    try:
        with path.open("rb") as stream:
            return tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as error:
        fail(f"manifest: {error}")


def feature_model(manifest):
    features = manifest.get("features", {})
    dependencies = manifest.get("dependencies", {})
    if not isinstance(features, dict) or not isinstance(dependencies, dict):
        fail("manifest features and dependencies must be tables")
    for name, values in features.items():
        if not isinstance(values, list) or any(not isinstance(value, str) for value in values):
            fail(f"manifest feature {name!r} must be an array of strings")
    optional = {name for name, value in dependencies.items()
                if isinstance(value, dict) and value.get("optional") is True}
    used_dep = {item[4:] for values in features.values() if isinstance(values, list)
                for item in values if isinstance(item, str) and item.startswith("dep:")}
    local = (set(features) - {"default"}) | (optional - used_dep)
    return features, dependencies, local, optional


def validate_feature(name, features, local, dependencies, optional, stack=()):
    if name not in local:
        fail(f"unknown feature {name!r}")
    if name in stack:
        fail(f"feature cycle: {' -> '.join((*stack, name))}")
    for value in features.get(name, []):
        if not isinstance(value, str):
            fail(f"manifest feature {name!r} contains a non-string value")
        if value.startswith("dep:"):
            dep = value[4:]
            if not dep or dep not in dependencies:
                fail(f"manifest feature {name!r} references unknown dependency {dep!r}")
            if dep not in optional:
                fail(f"manifest feature {name!r} uses dep:{dep} for a non-optional dependency")
            continue
        if "/" in value:
            dep, dependency_feature = value.split("/", 1)
            weak = dep.endswith("?")
            dep = dep.removesuffix("?")
            if not dep or dep not in dependencies:
                fail(f"manifest feature {name!r} references unknown dependency {dep!r}")
            if not dependency_feature or "/" in dependency_feature or "?" in dependency_feature:
                fail(f"manifest feature {name!r} has an invalid dependency feature reference")
            if weak and dep not in optional:
                fail(f"manifest feature {name!r} uses a weak feature reference for non-optional dependency {dep!r}")
            # Dependency features, including weak dep?/feature references, do not
            # add a local feature to the matrix closure.
            continue
        if value in local:
            validate_feature(value, features, local, dependencies, optional, (*stack, name))
        else:
            fail(f"manifest feature {name!r} references unknown feature {value!r}")


def workspace_packages(root, manifest):
    names = set()
    package = manifest.get("package", {})
    if isinstance(package, dict) and isinstance(package.get("name"), str):
        names.add(package["name"])
    members = manifest.get("workspace", {}).get("members", [])
    if isinstance(members, list):
        for member in members:
            if not isinstance(member, str):
                continue
            for member_manifest in root.glob(member + "/Cargo.toml"):
                child = read_manifest(member_manifest)
                child_package = child.get("package", {})
                if isinstance(child_package, dict) and isinstance(child_package.get("name"), str):
                    names.add(child_package["name"])
    return names


def validate(manifest_path, matrix_path):
    root = manifest_path.parent
    manifest = read_manifest(manifest_path)
    features, dependencies, local, optional = feature_model(manifest)
    errors = []
    try:
        matrix = json.loads(matrix_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        fail(f"matrix: {error}")
    if not isinstance(matrix, dict):
        fail("matrix must be an object")
    if type(matrix.get("version")) is not int or matrix.get("version") != 1:
        errors.append("matrix version must be 1")
    checks = matrix.get("checks")
    if not isinstance(checks, list):
        fail("matrix checks must be an array")
    if not checks:
        errors.append("matrix checks must not be empty")
    known_packages = workspace_packages(root, manifest)
    names = set()
    if "default" in features:
        default_model = dict(features)
        default_model["__matrix_default__"] = features["default"]
        try:
            validate_feature("__matrix_default__", default_model, local | {"__matrix_default__"},
                             dependencies, optional)
        except ValueError as error:
            errors.append(f"manifest default: {error}")
    for feature in sorted(local):
        try:
            validate_feature(feature, features, local, dependencies, optional)
        except ValueError as error:
            errors.append(f"manifest: {error}")
    for index, check in enumerate(checks):
        label = f"checks[{index}]"
        if not isinstance(check, dict):
            errors.append(f"{label} must be an object")
            continue
        unknown_fields = sorted(set(check) - CHECK_FIELDS)
        if unknown_fields:
            errors.append(f"{label} has unknown fields: {', '.join(unknown_fields)}")
        name = check.get("name")
        if not isinstance(name, str) or not name:
            errors.append(f"{label}.name must be a non-empty string")
        elif not ENTRY_NAME.fullmatch(name):
            errors.append(f"{label}.name contains characters unsupported by the matrix runner")
        elif name in names:
            errors.append(f"duplicate check name {name!r}")
        else:
            names.add(name)
        commands = check.get("commands")
        if not isinstance(commands, list) or not commands or any(not isinstance(c, str) for c in commands):
            errors.append(f"{label}.commands must be a non-empty array of strings")
            commands = []
        if len(set(commands)) != len(commands):
            errors.append(f"{label}.commands contains duplicate entries")
        for command in commands:
            if command not in COMMANDS:
                errors.append(f"{label}.commands contains unknown command {command!r}")
        packages = check.get("packages")
        if packages is not None:
            if not isinstance(packages, list) or any(not isinstance(p, str) for p in packages):
                errors.append(f"{label}.packages must be an array of strings")
                packages = []
            if len(set(packages)) != len(packages):
                errors.append(f"{label}.packages contains duplicate entries")
            for package_name in packages:
                if package_name not in known_packages:
                    errors.append(f"{label}.packages contains unknown package {package_name!r}")
        default_features = check.get("defaultFeatures", True)
        all_features = check.get("allFeatures", False)
        if not isinstance(default_features, bool):
            errors.append(f"{label}.defaultFeatures must be a boolean")
        if not isinstance(all_features, bool):
            errors.append(f"{label}.allFeatures must be a boolean")
            all_features = False
        requested = check.get("features", [])
        if not isinstance(requested, list) or any(not isinstance(f, str) for f in requested):
            errors.append(f"{label}.features must be an array of strings")
            requested = []
        if len(set(requested)) != len(requested):
            errors.append(f"{label}.features contains duplicate entries")
        for feature in requested:
            if "/" in feature:
                dependency, dependency_feature = feature.split("/", 1)
                if "?" in dependency:
                    errors.append(f"{label}.features contains unknown dependency feature {feature!r}")
                    continue
                dependency = dependency.removesuffix("?")
                if (not dependency or not dependency_feature or "/" in dependency_feature
                        or "?" in dependency_feature
                        or dependency not in dependencies):
                    errors.append(f"{label}.features contains unknown dependency feature {feature!r}")
            elif feature not in local:
                errors.append(f"{label}.features contains unknown feature {feature!r}")
        if all_features and requested:
            errors.append(f"{label} cannot combine allFeatures with explicit features")
    return sorted(errors)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    default_root = Path(__file__).resolve().parent.parent
    parser.add_argument("--manifest", type=Path, default=default_root / "Cargo.toml")
    parser.add_argument("--matrix", type=Path, default=default_root / ".infra/ci/cargo-matrix.json")
    args = parser.parse_args(argv)
    try:
        errors = validate(args.manifest, args.matrix)
    except ValueError as error:
        errors = [str(error)]
    if errors:
        for error in errors:
            print(f"feature-matrix: {error}", file=sys.stderr)
        return 1
    print("feature-matrix: valid")
    return 0


if __name__ == "__main__":
    sys.exit(main())
