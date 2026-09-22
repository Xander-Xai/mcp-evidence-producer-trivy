"""Safe, digest-bound npm package archive scan views."""
from __future__ import annotations
import gzip, hashlib, json, posixpath, shutil, tarfile, tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

POLICY = "package-archive-extraction-v1"
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_MEMBER_COUNT = 100_000
MAX_SINGLE_FILE_BYTES = 64 * 1024 * 1024
MAX_TOTAL_EXTRACTED_BYTES = 512 * 1024 * 1024
MAX_PATH_LENGTH = 4096

class ArchiveValidationError(ValueError):
    def __init__(self, reason: str):
        super().__init__(reason); self.reason = reason

def is_npm_archive(path: Path) -> bool:
    return path.name.lower().endswith(".tgz")

def _safe_member_path(name: str) -> str:
    if not name or "\x00" in name: raise ArchiveValidationError("archive_path_unsafe")
    if any(part == ".." for part in name.replace("\\", "/").split("/")):
        raise ArchiveValidationError("archive_path_unsafe")
    normalized = posixpath.normpath(name.replace("\\", "/"))
    if name.startswith(("/", "\\")) or PurePosixPath(normalized).is_absolute(): raise ArchiveValidationError("archive_path_unsafe")
    parts = normalized.split("/")
    if any(part in ("", ".", "..") for part in parts): raise ArchiveValidationError("archive_path_unsafe")
    if len(normalized.encode()) > MAX_PATH_LENGTH: raise ArchiveValidationError("archive_path_limit_exceeded")
    if not (normalized == "package" or normalized.startswith("package/")): raise ArchiveValidationError("archive_root_invalid")
    return normalized

def _manifest(root: Path):
    entries=[]; total=0
    for path in sorted(root.rglob("*")):
        if not path.is_file(): continue
        rel=path.relative_to(root).as_posix(); data=path.read_bytes(); total += len(data)
        entries.append({"path":rel,"size":len(data),"sha256":hashlib.sha256(data).hexdigest()})
    canonical=json.dumps(entries,ensure_ascii=False,separators=(",",":"),sort_keys=True).encode()
    return entries, hashlib.sha256(canonical).hexdigest(), total

@dataclass
class PackageArchiveView:
    source_snapshot: Path
    root: Path
    manifest_entries: list[dict[str, object]]
    manifest_sha256: str
    member_count: int
    total_regular_file_bytes: int
    _tempdir: tempfile.TemporaryDirectory[str]

    @classmethod
    def create(cls, source_snapshot: Path):
        if source_snapshot.stat().st_size > MAX_ARCHIVE_BYTES: raise ArchiveValidationError("archive_size_limit_exceeded")
        tempdir=tempfile.TemporaryDirectory(prefix="mcp-evidence-package-view-"); root=Path(tempdir.name)/"view"; root.mkdir(); seen=set(); count=0; total=0
        try:
            with source_snapshot.open("rb") as raw:
                try:
                    with tarfile.open(fileobj=gzip.GzipFile(fileobj=raw, mode="rb"), mode="r:") as archive:
                        for member in archive:
                            count += 1
                            if count > MAX_MEMBER_COUNT: raise ArchiveValidationError("archive_member_limit_exceeded")
                            name=_safe_member_path(member.name)
                            if member.isdir(): continue
                            if not member.isreg(): raise ArchiveValidationError("archive_member_type_unsupported")
                            if name in seen: raise ArchiveValidationError("archive_duplicate_path")
                            seen.add(name)
                            if member.size < 0 or member.size > MAX_SINGLE_FILE_BYTES: raise ArchiveValidationError("archive_member_size_limit_exceeded")
                            total += member.size
                            if total > MAX_TOTAL_EXTRACTED_BYTES: raise ArchiveValidationError("archive_total_size_limit_exceeded")
                            target=root/Path(*name.split("/")); target.parent.mkdir(parents=True,exist_ok=True); extracted=archive.extractfile(member)
                            if extracted is None: raise ArchiveValidationError("archive_extraction_failed")
                            with target.open("xb") as dst: shutil.copyfileobj(extracted,dst,1024*1024)
                            if target.stat().st_size != member.size: raise ArchiveValidationError("archive_extraction_failed")
                except (OSError, EOFError, tarfile.TarError, gzip.BadGzipFile) as exc:
                    raise ArchiveValidationError("archive_extraction_failed") from exc
            if not seen or any("/" not in p for p in seen): raise ArchiveValidationError("archive_root_missing")
            entries,digest,total=_manifest(root)
            return cls(source_snapshot,root,entries,digest,count,total,tempdir)
        except Exception:
            tempdir.cleanup(); raise

    def verify_unchanged(self):
        entries,digest,total=_manifest(self.root)
        if digest != self.manifest_sha256 or entries != self.manifest_entries or total != self.total_regular_file_bytes: raise ArchiveValidationError("archive_view_changed")

    def cleanup(self): self._tempdir.cleanup()
