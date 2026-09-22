# Package archive scan view — `package-archive-extraction-v1`

V1 supports only gzip-compressed npm `.tgz` packages with a single
`package/` root. The receipt remains bound to SHA-256 of the original archive;
Trivy scans a producer-owned derived filesystem view. Evidence records both
identities and uses scanner contract `trivy-fs-npm-package-view-v1`.

The controlled extractor rejects absolute paths, traversal, normalized escapes,
duplicate paths, symlinks, hardlinks, FIFO/device/socket/unknown special
members, missing or multiple roots, corrupt gzip/tar, and limits archive size
to 256 MiB, members to 100,000, one file to 64 MiB, total extracted regular
files to 512 MiB, and paths to 4096 UTF-8 bytes. Failures are fail-closed.

The canonical manifest contains sorted UTF-8 POSIX relative paths, sizes, and
SHA-256 values, serialized as compact sorted-key JSON. Its digest is the
derived-view identity and is never substituted for the original artifact
digest. The archive snapshot and derived manifest are verified before and
after scanning. Temporary absolute paths do not enter identity.

No Core schema change is required. Existing plain-file snapshots remain
unchanged. The threat model covers traversal, links, duplicate paths, bombs,
TOCTOU mutation, metadata ordering, and archives with identical extracted
contents but different original bytes.
