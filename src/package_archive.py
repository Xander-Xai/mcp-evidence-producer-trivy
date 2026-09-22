"""Safe, digest-bound npm package archive scan views."""
from __future__ import annotations
import gzip, hashlib, io, json, posixpath, shutil, tarfile, tempfile, zlib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

POLICY = "package-archive-extraction-v1"
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_DECOMPRESSED_BYTES = 768 * 1024 * 1024
MAX_MEMBER_COUNT = 100_000
MAX_SINGLE_FILE_BYTES = 64 * 1024 * 1024
MAX_TOTAL_EXTRACTED_BYTES = 512 * 1024 * 1024
MAX_PATH_LENGTH = 4096
SUPPORTED_NPM_DEPENDENCY_FILES = ("package-lock.json", "npm-shrinkwrap.json")

class ArchiveValidationError(ValueError):
    def __init__(self, reason: str):
        super().__init__(reason); self.reason = reason

def is_npm_archive(path: Path) -> bool:
    return path.name.lower().endswith(".tgz")

def _safe_member_path(name: str) -> str:
    try:
        if not name or "\x00" in name: raise ArchiveValidationError("archive_path_unsafe")
        if any(part == ".." for part in name.replace("\\", "/").split("/")): raise ArchiveValidationError("archive_path_unsafe")
        normalized = posixpath.normpath(name.replace("\\", "/"))
        if name.startswith(("/", "\\")) or PurePosixPath(normalized).is_absolute(): raise ArchiveValidationError("archive_path_unsafe")
        if any(part in ("", ".", "..") for part in normalized.split("/")): raise ArchiveValidationError("archive_path_unsafe")
        if len(normalized.encode("utf-8")) > MAX_PATH_LENGTH: raise ArchiveValidationError("archive_path_limit_exceeded")
    except UnicodeError as exc:
        raise ArchiveValidationError("archive_path_unsafe") from exc
    if not (normalized == "package" or normalized.startswith("package/")): raise ArchiveValidationError("archive_root_invalid")
    return normalized

class _BoundedReader(io.RawIOBase):
    def __init__(self, source, limit: int): self.source, self.limit, self.consumed = source, limit, 0
    def readable(self): return True
    def read(self, size=-1):
        if size is None or size < 0: size = self.limit - self.consumed + 1
        data = self.source.read(size); self.consumed += len(data)
        if self.consumed > self.limit: raise ArchiveValidationError("archive_decompressed_size_limit_exceeded")
        return data
    def readinto(self, buffer):
        data = self.read(len(buffer)); buffer[:len(data)] = data; return len(data)

def _validate_gzip(path: Path) -> None:
    dec = zlib.decompressobj(16 + zlib.MAX_WBITS); produced = 0
    try:
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                produced += len(dec.decompress(chunk, MAX_DECOMPRESSED_BYTES - produced + 1))
                if produced > MAX_DECOMPRESSED_BYTES: raise ArchiveValidationError("archive_decompressed_size_limit_exceeded")
                if dec.eof:
                    if dec.unused_data or stream.read(1): raise ArchiveValidationError("archive_gzip_trailing_data")
                    break
            else:
                if not dec.eof: raise ArchiveValidationError("archive_gzip_truncated")
    except ArchiveValidationError: raise
    except (OSError, EOFError, zlib.error) as exc: raise ArchiveValidationError("archive_gzip_integrity_failed") from exc

def _manifest(root: Path):
    entries = []; total = 0
    for path in sorted(root.rglob("*")):
        if not path.is_file(): continue
        rel = path.relative_to(root).as_posix(); data = path.read_bytes(); total += len(data)
        entries.append({"path": rel, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()})
    canonical = json.dumps(entries, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()
    return entries, hashlib.sha256(canonical).hexdigest(), total

def determine_scan_coverage(root: Path) -> dict[str, object]:
    candidates = []
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.relative_to(root).as_posix().startswith("package/") and path.name in SUPPORTED_NPM_DEPENDENCY_FILES:
            candidates.append(path.relative_to(root).as_posix())
    supported = []
    for rel in candidates:
        try: json.loads((root / rel).read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            return {"schema_version": "scan-coverage-v1", "status": "indeterminate", "candidate_targets": candidates, "supported_targets": [], "reason": "dependency_input_invalid"}
        supported.append(rel)
    if not supported:
        return {"schema_version": "scan-coverage-v1", "status": "no_supported_targets", "candidate_targets": candidates, "supported_targets": [], "reason": "no_supported_dependency_input"}
    return {"schema_version": "scan-coverage-v1", "status": "targets_present", "candidate_targets": candidates, "supported_targets": supported, "reason": "supported_dependency_input_present"}

@dataclass
class PackageArchiveView:
    source_snapshot: Path; root: Path; manifest_entries: list[dict[str, object]]; manifest_sha256: str; member_count: int; total_regular_file_bytes: int; _tempdir: tempfile.TemporaryDirectory[str]
    @classmethod
    def create(cls, source_snapshot: Path):
        if source_snapshot.stat().st_size > MAX_ARCHIVE_BYTES: raise ArchiveValidationError("archive_size_limit_exceeded")
        _validate_gzip(source_snapshot)
        tempdir = tempfile.TemporaryDirectory(prefix="mcp-evidence-package-view-"); root = Path(tempdir.name) / "view"; root.mkdir(); seen = set(); count = total = 0
        try:
            with source_snapshot.open("rb") as raw:
                bounded = _BoundedReader(gzip.GzipFile(fileobj=raw, mode="rb"), MAX_DECOMPRESSED_BYTES)
                with tarfile.open(fileobj=bounded, mode="r|") as archive:
                    for member in archive:
                        count += 1
                        if count > MAX_MEMBER_COUNT: raise ArchiveValidationError("archive_member_limit_exceeded")
                        name = _safe_member_path(member.name)
                        if member.isdir(): continue
                        if not member.isreg(): raise ArchiveValidationError("archive_member_type_unsupported")
                        if name in seen: raise ArchiveValidationError("archive_duplicate_path")
                        seen.add(name)
                        if member.size < 0 or member.size > MAX_SINGLE_FILE_BYTES: raise ArchiveValidationError("archive_member_size_limit_exceeded")
                        total += member.size
                        if total > MAX_TOTAL_EXTRACTED_BYTES: raise ArchiveValidationError("archive_total_size_limit_exceeded")
                        target = root / Path(*name.split("/")); target.parent.mkdir(parents=True, exist_ok=True); extracted = archive.extractfile(member)
                        if extracted is None: raise ArchiveValidationError("archive_extraction_failed")
                        with target.open("xb") as dst: shutil.copyfileobj(extracted, dst, 1024 * 1024)
                        if target.stat().st_size != member.size: raise ArchiveValidationError("archive_extraction_failed")
            if not seen or any("/" not in p for p in seen): raise ArchiveValidationError("archive_root_missing")
            entries, digest, total = _manifest(root); return cls(source_snapshot, root, entries, digest, count, total, tempdir)
        except (OSError, EOFError, tarfile.TarError) as exc:
            tempdir.cleanup(); raise ArchiveValidationError("archive_extraction_failed") from exc
        except Exception:
            tempdir.cleanup(); raise
    def verify_unchanged(self):
        entries, digest, total = _manifest(self.root)
        if digest != self.manifest_sha256 or entries != self.manifest_entries or total != self.total_regular_file_bytes: raise ArchiveValidationError("archive_view_changed")
    def cleanup(self): self._tempdir.cleanup()
