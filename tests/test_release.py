"""Tests for the deterministic release builder using synthetic test inputs."""

from __future__ import annotations

import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from scripts.build_release import ALLOWED_FILES, PACKAGE_NAME, ReleaseError, build_release


SAMPLE_SKILL = """---
name: internet-access-triage
description: Synthetic test input for release packaging.
metadata:
  version: 0.1.0
---

Synthetic sample content.
"""


class ReleaseBuilderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.root = Path(self.temp_dir.name)
        self.source = self.root / "source"
        self._create_source(self.source)

    @staticmethod
    def _create_source(source: Path) -> None:
        for relative in ALLOWED_FILES:
            path = source / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            if relative == "SKILL.md":
                content = SAMPLE_SKILL
            elif relative.endswith(".json"):
                content = '{"sample": true}\n'
            elif relative == "LICENSE":
                content = "Sample license text for isolated packaging tests.\n"
            else:
                content = f"# Sample content for {relative}\n"
            path.write_text(content, encoding="utf-8")

    def test_repeated_builds_produce_identical_archive_bytes(self) -> None:
        first = self.root / "first" / f"{PACKAGE_NAME}-0.1.0.zip"
        second = self.root / "second" / f"{PACKAGE_NAME}-0.1.0.zip"

        first_manifest = build_release(self.source, first)
        second_manifest = build_release(self.source, second)

        self.assertEqual(first.read_bytes(), second.read_bytes())
        self.assertEqual(first_manifest["archive"], second_manifest["archive"])
        self.assertEqual(
            first.with_suffix(".manifest.json").read_bytes(),
            second.with_suffix(".manifest.json").read_bytes(),
        )

    def test_archive_paths_are_exact_allowlist_under_single_skill_root(self) -> None:
        output = self.root / "release.zip"
        build_release(self.source, output)

        with zipfile.ZipFile(output) as archive:
            names = archive.namelist()
            expected = [f"{PACKAGE_NAME}/{path}" for path in sorted(ALLOWED_FILES)]
            self.assertEqual(names, expected)
            self.assertTrue(all(".." not in Path(name).parts for name in names))
            self.assertTrue(all(name.startswith(f"{PACKAGE_NAME}/") for name in names))
            self.assertTrue(all(info.date_time == (1980, 1, 1, 0, 0, 0) for info in archive.infolist()))

    def test_manifest_contains_archive_and_per_file_hashes(self) -> None:
        output = self.root / "release.zip"
        release_manifest = build_release(self.source, output)
        sidecar = json.loads(output.with_suffix(".manifest.json").read_text(encoding="utf-8"))

        self.assertEqual(sidecar, release_manifest)
        self.assertEqual(sidecar["version"], "0.1.0")
        self.assertEqual(sidecar["file_count"], len(ALLOWED_FILES))
        self.assertEqual(sidecar["archive"]["file"], output.name)
        self.assertEqual(len(sidecar["archive"]["sha256"]), 64)
        self.assertEqual(len(sidecar["files"]), len(ALLOWED_FILES))
        self.assertTrue(all(len(item["sha256"]) == 64 for item in sidecar["files"]))

    def test_missing_required_file_is_rejected(self) -> None:
        (self.source / "config/defaults.json").unlink()

        with self.assertRaisesRegex(ReleaseError, "Missing required release files: config/defaults.json"):
            build_release(self.source, self.root / "release.zip")

    def test_unexpected_file_is_rejected(self) -> None:
        extra = self.source / "research" / "notes.md"
        extra.parent.mkdir()
        extra.write_text("Sample unexpected content.\n", encoding="utf-8")

        with self.assertRaisesRegex(ReleaseError, "Unexpected source entries: research/"):
            build_release(self.source, self.root / "release.zip")

    def test_python_caches_are_excluded_from_archive(self) -> None:
        cache_dir = self.source / "scripts/netops/__pycache__"
        cache_dir.mkdir()
        (cache_dir / "runner.cpython-311.pyc").write_bytes(b"sample compiled cache bytes")
        (self.source / "scripts/netops/runtime.pyc").write_bytes(b"sample compiled cache bytes")
        output = self.root / "release.zip"

        build_release(self.source, output)

        with zipfile.ZipFile(output) as archive:
            names = archive.namelist()
        self.assertFalse(any("__pycache__" in name or name.endswith(".pyc") for name in names))
        self.assertEqual(len(names), len(ALLOWED_FILES))

    def test_symlink_is_rejected(self) -> None:
        link = self.source / "unexpected-link"
        target = self.root / "outside.txt"
        target.write_text("sample", encoding="utf-8")
        try:
            link.symlink_to(target)
        except (NotImplementedError, OSError) as exc:
            self.skipTest(f"Symlinks are unavailable in this environment: {exc}")

        with self.assertRaisesRegex(ReleaseError, "Symlinks are not allowed"):
            build_release(self.source, self.root / "release.zip")

    def test_symlinked_python_cache_is_rejected_without_following_it(self) -> None:
        target = self.root / "cache-target"
        target.mkdir()
        cache_link = self.source / "scripts/netops/__pycache__"
        try:
            cache_link.symlink_to(target, target_is_directory=True)
        except (NotImplementedError, OSError) as exc:
            self.skipTest(f"Symlinks are unavailable in this environment: {exc}")

        with self.assertRaisesRegex(ReleaseError, "Symlinks are not allowed.*__pycache__"):
            build_release(self.source, self.root / "release.zip")

    def test_non_utf8_or_binary_source_is_rejected(self) -> None:
        (self.source / "scripts/netops/urls.py").write_bytes(b"\x00\xff")

        with self.assertRaisesRegex(ReleaseError, "not UTF-8 text"):
            build_release(self.source, self.root / "release.zip")

    def test_existing_archive_is_never_overwritten(self) -> None:
        output = self.root / "release.zip"
        original = b"existing user data"
        output.write_bytes(original)

        with self.assertRaisesRegex(ReleaseError, "Refusing to overwrite"):
            build_release(self.source, output)

        self.assertEqual(output.read_bytes(), original)
        self.assertFalse(output.with_suffix(".manifest.json").exists())

    def test_existing_manifest_prevents_partial_release_output(self) -> None:
        output = self.root / "release.zip"
        manifest = output.with_suffix(".manifest.json")
        original = b"existing manifest data"
        manifest.write_bytes(original)

        with self.assertRaisesRegex(ReleaseError, "Refusing to overwrite"):
            build_release(self.source, output)

        self.assertFalse(output.exists())
        self.assertEqual(manifest.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
