import gzip
import io
import tarfile
from pathlib import Path

import pytest

from src.package_archive import ArchiveValidationError, PackageArchiveView


def make_tgz(path: Path, members):
    with path.open("wb") as raw:
        with gzip.GzipFile(fileobj=raw, mode="wb") as gz:
            with tarfile.open(fileobj=gz, mode="w:") as tar:
                for name, data, kind in members:
                    info = tarfile.TarInfo(name)
                    if kind == "file":
                        info.size = len(data)
                        tar.addfile(info, io.BytesIO(data))
                    else:
                        info.type = kind
                        tar.addfile(info)


def test_valid_npm_archive_has_stable_manifest(tmp_path):
    archive = tmp_path / "pkg.tgz"
    make_tgz(archive, [("package/package.json", b"{}", "file"), ("package/index.js", b"x", "file")])
    view = PackageArchiveView.create(archive)
    assert view.manifest_sha256
    assert view.member_count == 2
    view.verify_unchanged()


@pytest.mark.parametrize("name", ["../evil", "/etc/passwd", "package/../evil"])
def test_unsafe_paths_fail_closed(tmp_path, name):
    archive = tmp_path / "bad.tgz"
    make_tgz(archive, [(name, b"x", "file")])
    with pytest.raises(ArchiveValidationError) as exc:
        PackageArchiveView.create(archive)
    assert exc.value.reason == "archive_path_unsafe"


def test_links_and_missing_root_fail_closed(tmp_path):
    link = tmp_path / "link.tgz"
    make_tgz(link, [("package/link", b"", tarfile.SYMTYPE)])
    with pytest.raises(ArchiveValidationError) as exc:
        PackageArchiveView.create(link)
    assert exc.value.reason == "archive_member_type_unsupported"

    missing = tmp_path / "missing.tgz"
    make_tgz(missing, [("other/file", b"x", "file")])
    with pytest.raises(ArchiveValidationError) as exc:
        PackageArchiveView.create(missing)
    assert exc.value.reason == "archive_root_invalid"


def test_duplicate_normalized_paths_fail_closed(tmp_path):
    archive = tmp_path / "dupe.tgz"
    make_tgz(archive, [("package/a", b"a", "file"), ("package/a", b"b", "file")])
    with pytest.raises(ArchiveValidationError) as exc:
        PackageArchiveView.create(archive)
    assert exc.value.reason == "archive_duplicate_path"


def test_derived_view_mutation_is_detected(tmp_path):
    archive = tmp_path / "pkg.tgz"
    make_tgz(archive, [("package/a", b"a", "file")])
    view = PackageArchiveView.create(archive)
    (view.root / "package" / "a").write_bytes(b"changed")
    with pytest.raises(ArchiveValidationError) as exc:
        view.verify_unchanged()
    assert exc.value.reason == "archive_view_changed"
