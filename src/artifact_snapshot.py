"""Producer-owned immutable scan snapshots for file-based scanners."""

from __future__ import annotations

import hashlib
import os
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path


@dataclass
class ArtifactSnapshot:
    source_ref: str
    scan_path: Path
    sha256: str
    size: int
    _tempdir: tempfile.TemporaryDirectory[str]

    @classmethod
    def create(cls, source: Path) -> "ArtifactSnapshot":
        tempdir = tempfile.TemporaryDirectory(prefix="mcp-evidence-snapshot-")
        try:
            target = Path(tempdir.name) / (source.name or "artifact.bin")
            with source.open("rb") as src, target.open("wb") as dst:
                shutil.copyfileobj(src, dst, length=1024 * 1024)
                dst.flush()
                os.fsync(dst.fileno())
            digest = hashlib.sha256()
            size = 0
            with target.open("rb") as materialized:
                for chunk in iter(lambda: materialized.read(1024 * 1024), b""):
                    digest.update(chunk)
                    size += len(chunk)
            return cls(str(source), target, digest.hexdigest(), size, tempdir)
        except Exception:
            tempdir.cleanup()
            raise

    def verify_unchanged(self) -> None:
        digest = hashlib.sha256()
        size = 0
        with self.scan_path.open("rb") as materialized:
            for chunk in iter(lambda: materialized.read(1024 * 1024), b""):
                digest.update(chunk)
                size += len(chunk)
        if digest.hexdigest() != self.sha256 or size != self.size:
            raise ValueError("artifact_snapshot_changed")

    def cleanup(self) -> None:
        self._tempdir.cleanup()

