#!/usr/bin/env python3
"""Build a deterministic ZIP release of the internet-access-triage skill."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import zipfile
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path, PurePosixPath


PACKAGE_NAME = "internet-access-triage"
SKILL_ROOT_NAME = PACKAGE_NAME
ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)

# Keep this list explicit. New runtime files must be reviewed and added here.
ALLOWED_FILES = (
    "LICENSE",
    "SKILL.md",
    "config/defaults.json",
    "references/collection-limits.md",
    "references/evidence-contract.md",
    "schemas/diagnosis.schema.json",
    "schemas/evidence.schema.json",
    "scripts/diagnose.py",
    "scripts/netops/__init__.py",
    "scripts/netops/contract.py",
    "scripts/netops/diagnosis.py",
    "scripts/netops/live.py",
    "scripts/netops/pcap.py",
    "scripts/netops/report.py",
    "scripts/netops/runner.py",
    "scripts/netops/urls.py",
)

ALLOWED_DIRECTORIES = frozenset(
    {
        "config",
        "references",
        "schemas",
        "scripts",
        "scripts/netops",
    }
)


class ReleaseError(Exception):
    """Raised when the source tree or release destination is invalid."""


@dataclass(frozen=True)
class ReleaseFile:
    relative_path: str
    content: bytes


def _validate_allowlist() -> None:
    for value in ALLOWED_FILES:
        path = PurePosixPath(value)
        if path.is_absolute() or ".." in path.parts or "\\" in value:
            raise RuntimeError(f"Unsafe path in release allowlist: {value!r}")
        if value != path.as_posix():
            raise RuntimeError(f"Non-canonical path in release allowlist: {value!r}")


def _read_source(source_dir: Path) -> tuple[list[ReleaseFile], str]:
    try:
        source_mode = source_dir.lstat().st_mode
    except OSError as exc:
        raise ReleaseError(f"Cannot access source directory {source_dir}: {exc}") from exc
    if stat.S_ISLNK(source_mode):
        raise ReleaseError(f"Source directory must not be a symlink: {source_dir}")
    if not stat.S_ISDIR(source_mode):
        raise ReleaseError(f"Source path is not a directory: {source_dir}")

    allowed_files = set(ALLOWED_FILES)
    found_files: set[str] = set()
    unexpected: list[str] = []

    def visit(directory: Path, relative_directory: str) -> None:
        try:
            with os.scandir(directory) as scanner:
                entries = sorted(scanner, key=lambda entry: entry.name)
        except OSError as exc:
            raise ReleaseError(f"Cannot inspect source directory {directory}: {exc}") from exc

        for entry in entries:
            if entry.name in {".", ".."} or "/" in entry.name or "\\" in entry.name:
                unexpected.append(str(Path(relative_directory) / entry.name))
                continue
            relative = f"{relative_directory}/{entry.name}" if relative_directory else entry.name
            try:
                entry_mode = entry.stat(follow_symlinks=False).st_mode
            except OSError as exc:
                raise ReleaseError(f"Cannot inspect source entry {relative}: {exc}") from exc

            if stat.S_ISLNK(entry_mode):
                raise ReleaseError(f"Symlinks are not allowed in the release source: {relative}")
            if stat.S_ISDIR(entry_mode):
                if entry.name == "__pycache__":
                    continue
                if relative not in ALLOWED_DIRECTORIES:
                    unexpected.append(relative + "/")
                else:
                    visit(Path(entry.path), relative)
            elif stat.S_ISREG(entry_mode):
                if entry.name.endswith(".pyc"):
                    continue
                if relative not in allowed_files:
                    unexpected.append(relative)
                else:
                    found_files.add(relative)
            else:
                raise ReleaseError(f"Only regular text files are allowed: {relative}")

    visit(source_dir, "")

    if unexpected:
        unexpected.sort()
        raise ReleaseError("Unexpected source entries: " + ", ".join(unexpected))

    missing = sorted(allowed_files - found_files)
    if missing:
        raise ReleaseError("Missing required release files: " + ", ".join(missing))

    files: list[ReleaseFile] = []
    for relative in sorted(ALLOWED_FILES):
        file_path = source_dir.joinpath(*PurePosixPath(relative).parts)
        try:
            content = file_path.read_bytes()
        except OSError as exc:
            raise ReleaseError(f"Cannot read required release file {relative}: {exc}") from exc
        try:
            content.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ReleaseError(f"Release file is not UTF-8 text: {relative}") from exc
        if any(byte == 0 or (byte < 32 and byte not in (9, 10, 13)) for byte in content):
            raise ReleaseError(f"Release file contains binary control bytes: {relative}")
        files.append(ReleaseFile(relative, content))

    skill_text = next(item.content.decode("utf-8") for item in files if item.relative_path == "SKILL.md")
    version = _skill_version(skill_text)
    return files, version


def _skill_version(skill_text: str) -> str:
    if not skill_text.startswith("---\n"):
        raise ReleaseError("SKILL.md must start with YAML front matter")
    closing = skill_text.find("\n---\n", 4)
    if closing < 0:
        raise ReleaseError("SKILL.md has no closing YAML front matter delimiter")
    front_matter = skill_text[4:closing]

    name_match = re.search(r"^name:\s*([A-Za-z0-9][A-Za-z0-9-]*)\s*$", front_matter, re.MULTILINE)
    if name_match is None or name_match.group(1) != PACKAGE_NAME:
        raise ReleaseError(f"SKILL.md name must be {PACKAGE_NAME!r}")

    metadata_match = re.search(
        r"^metadata:\s*\n((?:^[ \t]+[^\n]*\n?)*)",
        front_matter,
        re.MULTILINE,
    )
    if metadata_match is None:
        raise ReleaseError("SKILL.md front matter must include metadata.version")
    version_match = re.search(
        r"^[ \t]+version:\s*([0-9]+\.[0-9]+\.[0-9]+)\s*$",
        metadata_match.group(1),
        re.MULTILINE,
    )
    if version_match is None:
        raise ReleaseError("SKILL.md metadata.version must use numeric major.minor.patch form")
    return version_match.group(1)


def _make_zip(files: list[ReleaseFile]) -> bytes:
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, mode="w", allowZip64=False) as archive:
        archive.comment = b""
        for item in files:
            archive_path = f"{SKILL_ROOT_NAME}/{item.relative_path}"
            info = zipfile.ZipInfo(archive_path, date_time=ZIP_TIMESTAMP)
            info.create_system = 3
            info.compress_type = zipfile.ZIP_STORED
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            info.extra = b""
            info.comment = b""
            archive.writestr(info, item.content)
    return buffer.getvalue()


def _write_exclusive(path: Path, content: bytes) -> None:
    created = False
    try:
        with path.open("xb") as output:
            created = True
            output.write(content)
    except OSError:
        if created:
            try:
                path.unlink()
            except OSError:
                pass
        raise


def build_release(
    source_dir: str | Path,
    output_zip: str | Path,
    manifest_path: str | Path | None = None,
) -> dict[str, object]:
    """Build a ZIP and sidecar manifest, refusing to overwrite either file."""
    _validate_allowlist()
    source = Path(source_dir)
    output = Path(output_zip)
    if output.suffix.lower() != ".zip":
        raise ReleaseError("Release output path must end in .zip")
    manifest = Path(manifest_path) if manifest_path is not None else output.with_suffix(".manifest.json")
    if output.absolute() == manifest.absolute():
        raise ReleaseError("ZIP output and manifest must use different paths")

    files, version = _read_source(source)
    source_resolved = source.resolve()
    if output.resolve(strict=False).is_relative_to(source_resolved):
        raise ReleaseError("Release output must be outside the source skill directory")
    if manifest.resolve(strict=False).is_relative_to(source_resolved):
        raise ReleaseError("Release manifest must be outside the source skill directory")

    archive_bytes = _make_zip(files)
    archive_digest = hashlib.sha256(archive_bytes).hexdigest()
    archive_relative_files = [
        {
            "path": f"{SKILL_ROOT_NAME}/{item.relative_path}",
            "sha256": hashlib.sha256(item.content).hexdigest(),
            "size_bytes": len(item.content),
        }
        for item in files
    ]
    release_manifest: dict[str, object] = {
        "package": PACKAGE_NAME,
        "version": version,
        "archive": {
            "file": output.name,
            "sha256": archive_digest,
            "size_bytes": len(archive_bytes),
        },
        "file_count": len(files),
        "files": archive_relative_files,
    }
    manifest_bytes = (json.dumps(release_manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")

    output.parent.mkdir(parents=True, exist_ok=True)
    manifest.parent.mkdir(parents=True, exist_ok=True)
    created: list[Path] = []
    try:
        _write_exclusive(output, archive_bytes)
        created.append(output)
        _write_exclusive(manifest, manifest_bytes)
        created.append(manifest)
    except FileExistsError as exc:
        for path in reversed(created):
            try:
                path.unlink()
            except OSError:
                pass
        raise ReleaseError(f"Refusing to overwrite existing release output: {exc.filename or exc}") from exc
    except OSError:
        for path in reversed(created):
            try:
                path.unlink()
            except OSError:
                pass
        raise

    return release_manifest


def main(argv: list[str] | None = None) -> int:
    repository_root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source",
        type=Path,
        default=repository_root / "skills" / PACKAGE_NAME,
        help="skill source directory (default: repository runtime directory)",
    )
    parser.add_argument("--out", required=True, type=Path, help="new ZIP output path")
    parser.add_argument(
        "--manifest",
        type=Path,
        help="sidecar manifest path (default: same path with .manifest.json suffix)",
    )
    args = parser.parse_args(argv)

    try:
        release_manifest = build_release(args.source, args.out, args.manifest)
    except (ReleaseError, OSError) as exc:
        print(f"release build failed: {exc}", file=sys.stderr)
        return 2

    archive = release_manifest["archive"]
    assert isinstance(archive, dict)
    manifest_path = args.manifest or args.out.with_suffix(".manifest.json")
    print(f"Built {PACKAGE_NAME} {release_manifest['version']}")
    print(f"ZIP: {args.out} ({archive['size_bytes']} bytes, sha256 {archive['sha256']})")
    print(f"Manifest: {manifest_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
