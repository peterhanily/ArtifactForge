# Known tells

ArtifactForge output is deterministic synthetic data. Every format below says how it differs
from the real thing, because a generator that hides its limitations is worse than one that
has them.

This file is enforced. `tests/test_known_tells.py` fails if a format the code can emit has no
section here, and equally if a section here names no emitted format — so it cannot drift out
of date silently. It is the prose half of `fidelity-scorecard.json`, whose `honest_gaps` array
carries the same information in a form a machine can read.

Generated binaries are payload-free by construction, under the precise executable-code checks
and limitations documented in
[`docs/inert-by-construction.md`](docs/inert-by-construction.md).

## pe

- **Payload-free.** The `.text` section starts with one `0xC3` (`ret`) and the rest is zero
  padding. The fixed DOS stub separately prints its standard sentence and exits.
- **Minimal, not compiler-realistic.** Two sections (`.text`, `.rdata`), no resources, no rich
  header, no relocations, no TLS. The internals do not resemble any real compiler's output,
  and pefile will note that a large fraction of the file is zero bytes.
- **IMPHASH is real.** A genuine, seed-deterministic import table across common DLLs
  (kernel32, advapi32, user32, ws2_32). pefile and LIEF independently enumerate the DLL and
  function sequence, each confirms pefile/VT-normalised IMPHASH semantics, and Gate 1 requires
  their results to agree. The imported functions are a plausible selection, not a real
  program's.
- **`TimeDateStamp` is pinned to 0** so the bytes never depend on a clock.
- **The MS-DOS header and stub are the standard MSVC ones**, byte for byte, including the
  "This program cannot be run in DOS mode." message. A PE without them is trivially
  distinguishable from a real one — the community rule `HasModified_DOS_Message` fires on
  every binary that omits the message. The stub is 16-bit code that prints a sentence and
  exits, and Gate 3 requires it byte-exact, because it is the one region of a PE where
  arbitrary code is conventional and nothing reads it.
- **Marked.** The overlay carries `ARTIFACTFORGE-SYNTHETIC-<16 hex>`.

## macho

- **Payload-free.** `__text` is `mov w0, #0 ; ret` and nothing else — the arm64 analogue of
  the PE's single `ret`. It is a genuinely loadable, ad-hoc-signed executable, because an
  unsigned arm64 binary is not loadable at all and so would not be a realistic artifact.
  Running it returns zero.
- **symhash and cdhash are real.** A genuine `LC_SYMTAB` whose undefined external symbols
  yield the same symhash threatstream/symhash and yara-x compute, and an ad-hoc
  `CS_SuperBlob` whose cdhash is what `codesign -d` reports.
- **Thin arm64, not fat.** A single-architecture `MH_EXECUTE`, where a shipped macOS binary is
  often universal.
- **Older linker idiom.** Uses `LC_DYLD_INFO_ONLY` bind opcodes. A 2024-era clang emits
  `LC_DYLD_CHAINED_FIXUPS`, `LC_FUNCTION_STARTS`, `LC_DATA_IN_CODE` and an exports trie, and
  none of those are present — `dyld_info -fixup_chains` will show nothing.
- **Ad-hoc signature only.** No Developer ID, no notarisation, no Info.plist slot. A dated manual
  scan recorded Gatekeeper rejection; that is not a portable guarantee across hosts or macOS
  releases, and a future assessment needs a functioning platform control.
- **Marked.** `__TEXT,__cstring` carries `ARTIFACTFORGE-SYNTHETIC-<16 hex>`.

## hive

- **Minimal regf.** One hive bin, a single shared empty security descriptor for every key,
  `lf` subkey lists only, no classes, no big-data records. Enough for regipy and libregf, and
  sparser than any real hive.
- **ASCII-only key and value names.** Names are encoded latin-1 under the `KEY_COMP_NAME`
  flag. A localised autostart name will not round-trip: characters above U+00FF raise, and
  U+0080–U+00FF encode without error but read back wrong. Value *data* is UTF-16 and is fine.
- **Pinned timestamps.** Every `last_written` and the hbin time are fixed constants.
- **Marked.** The base block's hive name is `ArtifactForgeHive` (UTF-16).

## prefetch

- **Uncompressed SCCA v17; legacy scenes say Windows 10.** Format version 17 is the Windows XP
  and Server 2003 layout. A real `10.0.19045` host emits version 30,
  MAM/LZXPRESS-compressed, and a responder who checks a benchmark/gallery `HostProfile` will
  see them disagree. Fixture Core avoids a version claim by naming this combination
  `windows-loose-v1`; it does not make the artifacts internally version-consistent. v17 is
  emitted because it is uncompressed and open-source parsers read it directly. This is the
  largest single fidelity gap in the Windows set.
- **Single volume, no directory strings, no file references.** A real record carries the full
  directory list and the MFT references of everything the process touched.
- **The SCCA XP path hash is real.** It hashes the upper-case UTF-16LE device path using the
  v17-era algorithm; the multiply-by-37 `ConvKey` is only its intermediate value. Gate 1
  independently re-parses the modeled path and binds the resulting hash to both the header
  and on-disk filename.
- **Pinned run time and volume serial.**
- **Marked.** A reserved entry in the filename strings array.

## sqlite

Covers knowledgeC, TCC and QuarantineEventsV2.

- **Minimal schema.** Only the tables and columns real forensic queries read are present. A
  genuine database has many more columns, supporting tables, indices and triggers.
- **The SQLite header embeds the writing library's version**, and these are the only artifacts
  affected. Measured: a gallery built on macOS/arm64 with sqlite3 3.50.4 and rebuilt on
  Linux/x86-64 with 3.53.1 differs in exactly these three files and in nothing else — every
  PE, Mach-O, registry hive, prefetch record, plist and answer key is byte-identical across
  both operating system and architecture. The version in use is recorded in
  `fidelity-scorecard.json` and beside each sample.
- **Not independently validated.** `sqlite3` both writes and reads these files, so it is not
  an independent oracle. Gate 1 records this as a declared gap rather than counting it as
  validation.
- **Pinned timestamps and rowids.** Mac absolute time from the scenario, never a clock.
- **Marked.** A reserved `artifactforge_synthetic` table.

## plist

- **LaunchAgent only**, with a minimal key set and a pinned `StartInterval`.
- **Not independently validated.** `plistlib` both writes and reads it — the same gap as
  SQLite, declared the same way.
- **Marked.** A reserved `artifactforge_synthetic` key. launchd ignores keys it does not know.

## Not emitted at all

The quarantine xattr value is written as a **sidecar file**, not applied as a real extended
attribute — nothing this project does touches a real file's metadata.

Disk images, memory dumps, EVTX, ShimCache, LNK, FSEvents and unified logs are not generated.
The tier is loose files that a responder's tools read directly.

## EvidenceForge coupling

`artifactforge/ef_seeds.py` recovers a Sysmon-local logical identity from EvidenceForge's
seed-derived hash fields by reproducing upstream's private Sysmon seed construction. That is a
private surface SemVer does not protect. It is pinned to `v1.13.1`, isolated in one module
nothing else imports, absent from the public exports, and exercised by isolated contract jobs
that fail rather than skip when their required EvidenceForge installation is missing — so an
upstream change to those formulas breaks loudly. The stock branch-office run has no
basename-matched Sysmon/Zeek pair, so this recovery is not evidence that one logical file
received inconsistent values across emitters.
