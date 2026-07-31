# Known Tells

ArtifactForge output is deterministic synthetic data. Honesty is a shipped mechanism: every
format discloses how it differs from a real artifact. CI fails if a format ships without an
entry here. This is a training/evaluation tool — its artifacts must never be presentable as
genuine evidence.

## ContentStore PE stubs

- **Inert.** The `.text` section is a single `0xC3` (`ret`); the stub is structurally valid
  but does nothing. It is not, and cannot be, functional malware.
- **Minimal / not compiler-realistic.** Two sections (`.text`, `.rdata`), no resources, no
  rich header — internals do not resemble a real compiler's output.
- **IMPHASH is real** — the stub carries a genuine, seed-deterministic import table across
  common DLLs (kernel32/advapi32/user32/ws2_32), so pefile computes a stable IMPHASH. The
  imported functions are a plausible but synthetic selection, not a real program's imports.
- **Pinned `TimeDateStamp = 0`** so bytes never depend on the wall clock.
- **Fixed marker string** (`ARTIFACTFORGE-SYNTHETIC-<8 hex>`) in the overlay — an explicit,
  greppable synthetic anchor.

## Registry hives (Run-key, Amcache)

- **Minimal regf.** One hive bin, a single shared empty security descriptor for every key,
  `lf` subkey lists only. Sufficient for open-source parsers (regipy) but sparser than a
  real hive.
- **Pinned timestamps** (all `last_written` / hbin times fixed) — deterministic, not
  wall-clock.

## Prefetch

- **Uncompressed SCCA v17.** Real Windows 10 prefetch is MAM/LZXPRESS-compressed; ArtifactForge
  emits the older uncompressed format, which open-source parsers read directly. MAM
  compression is out of scope.
- **Single volume, no directory strings** (`dirStringsCount = 0`); pinned run time.

## macOS SQLite artifacts (knowledgeC, TCC, QuarantineEventsV2)

- **Minimal schema.** Only the tables/columns real forensic queries (APOLLO-style) read are
  present; a real database has many more columns and supporting tables.
- **SQLite header embeds the writing library version.** Two builds with the same `sqlite3`
  are byte-identical (the two-clock gate), but a different SQLite version produces different
  header bytes — cross-version reproducibility is not guaranteed.
- **Pinned timestamps and rowids** (Mac absolute time from the canonical event, not the clock).

## macOS quarantine xattr and LaunchAgent

- **No real xattr is set.** The `com.apple.quarantine` value is emitted as data (a sidecar
  file), not applied as a real extended attribute on the host.
- **LaunchAgent** is a binary plist with a minimal key set; pinned `StartInterval`.

## Log hash reconciliation

- ArtifactForge patches hash fields in a **copy** of EvidenceForge's output; the upstream tool is
  never modified. Recovered identity relies on EF's seed formulas (pinned to v1.12.0); an EF
  version bump can change them and must be re-verified.
