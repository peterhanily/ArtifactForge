# Inert by construction

ArtifactForge generates files shaped like malware. That is the point — a responder practising
on a scene with no binary in it is not practising — and it is also the thing most worth being
careful about. This document says what "inert" means here precisely, and names the tests that
enforce it, because a safety property nobody checks is a safety claim.

## The rule

A generated binary reproduces the forensic **signal** and never the offensive **capability**.

It has a real import table, a real symbol table, a real hash, a real signature — everything a
responder's tools read and pivot on. It has no payload, no network code, no shell, no
persistence mechanism of its own, and no decryption routine. There is nothing in it to
reverse-engineer because there is nothing in it.

Concretely, the entire code body of each format is:

| Format | Region | Code | Bytes |
|---|---|---|---|
| PE (x86-64) | `.text` | `ret` | `C3` |
| PE (16-bit) | MS-DOS stub | print a sentence, exit | `0E 1F BA 0E 00 B4 09 CD 21 B8 01 4C CD 21` |
| Mach-O (arm64) | `__text` | `mov w0, #0 ; ret` | `52 80 00 00  D6 5F 03 C0` |

Everything after that is zero padding. Gate 3 reads what actually lands on disk and fails if a
single instruction appears past the return.

The DOS stub is the standard one every Windows compiler has emitted for thirty years,
reproduced byte for byte. It is included because a PE without it is trivially distinguishable
from a real binary, and it is the one region of a PE where arbitrary code is conventional and
nothing ever reads it — so Gate 3 requires it to equal the canonical bytes exactly, closing the
obvious place to hide something. `tests/test_gate_mutations.py` overwrites four bytes of it and
requires the gate to notice.

## Why the Mach-O is signed and loadable

This is the one place where the honest answer is uncomfortable, so it is stated plainly.

An unsigned arm64 macOS binary will not load at all. A synthetic Mach-O that cannot load is
not a realistic artifact — its signature is missing, its `cdhash` does not exist, and
`codesign` refuses it, so every tool a responder would point at it disagrees with a real one.
To be worth generating it has to be ad-hoc signed, and to be deterministic that signature has
to be computed in-process rather than applied afterwards.

The consequence is that the file is genuinely executable. Running it does exactly one thing:
it returns zero. That is a real step up in dual-use posture from an unloadable stub, and the
mitigation is the whole of this document — the two-instruction body, the marker, the
disclosure, and the tests below.

## Marked, in-band, in every format

A bundle can be renamed and a README can be lost. The only disclosure that survives a file
being copied somewhere else is one inside the bytes, so every format carries an
`ARTIFACTFORGE` anchor that `strings` finds:

| Format | Where |
|---|---|
| PE | overlay: `ARTIFACTFORGE-SYNTHETIC-<16 hex>` |
| Mach-O | `__TEXT,__cstring`: `ARTIFACTFORGE-SYNTHETIC-<16 hex>` |
| Registry hive | the base block's hive name, `ArtifactForgeHive` (UTF-16) |
| Prefetch | a reserved filename-strings entry |
| SQLite (knowledgeC, TCC, QuarantineEventsV2) | a reserved `artifactforge_synthetic` table |
| Binary plist | a reserved `artifactforge_synthetic` key |

The disclosure text is deliberately plain ASCII. A binary plist silently re-encodes any string
containing a non-ASCII character as UTF-16, which would hide the anchor from `strings` — a
marker has to survive every container it is put in, not most of them.

## Indicators point nowhere real

No generated artifact may name something that could exist. Domains are RFC 2606 reserved
(`.example`, `.invalid`, `.test`); addresses are RFC 5737 / RFC 3849 documentation ranges or
RFC 1918 private ones; and no bundle identifier may sit under a real vendor's reverse-DNS
prefix. That last one matters more than it looks: on macOS the identifier is embedded in the
code signature, so an ad-hoc-signed synthetic binary calling itself `com.apple.Notes` is
asserting something false about Apple. Windows executable *filenames* are deliberately not
policed — `chrome.exe` is ubiquitous on a real host and claims nothing about who wrote it. Gate 3 scans the emitted bytes of every artifact for URLs and addresses
and fails on anything outside those ranges — so this is enforced against the file, not against
the pool the file was drawn from.

## Checkable, not asserted

Every claim above is a test. These are the ones that would go red:

| Property | Enforced by |
|---|---|
| The PE's `.text` is one `ret` and padding | `gates/inertness.py::_pe_code_is_inert` |
| The PE's MS-DOS stub is the canonical one, byte for byte | same |
| The Mach-O's `__text` is `mov w0,#0 ; ret` | `gates/inertness.py::_macho_code_is_inert` |
| Every emitted format carries its marker | `gates/inertness.py::run`, `MARKERS` table |
| A format with no declared marker fails | same — an unknown format is a failure, not a skip |
| No URL outside RFC 2606 | `gates/inertness.py::_indicator_hygiene` |
| No address outside RFC 5737 / RFC 1918 | same |
| No bundle identifier under a real vendor's prefix | same, `_REAL_VENDOR_PREFIXES` |
| Stripping a marker turns Gate 3 red | `tests/test_gate_mutations.py::test_inertness_reddens_when_the_synthetic_marker_is_stripped` |
| Code past the `ret` turns Gate 3 red | `tests/test_gate_mutations.py::test_inertness_reddens_when_the_code_section_is_not_inert` |
| Tampering with the DOS stub turns Gate 3 red | `tests/test_gate_mutations.py::test_inertness_reddens_when_the_dos_stub_is_tampered_with` |
| A routable domain turns Gate 3 red | `tests/test_gate_mutations.py::test_inertness_reddens_when_an_indicator_could_be_real` |
| A real vendor's bundle id turns Gate 3 red | `tests/test_gate_mutations.py::test_inertness_reddens_when_a_bundle_id_names_a_real_vendor` |

The mutation tests are the load-bearing ones. A gate that has never been observed to fail
proves nothing, so each of these breaks the property on purpose and requires the gate to
notice.

## What real scanners make of it

Run with `scripts/scan-exposure.sh` against a fresh 20-scenario batch plus the committed
gallery — 160 files. Every scanner is preceded by a positive control, because one that detects
nothing because it is misconfigured is indistinguishable from a clean result.

Measured 2026-07-31 on macOS 26.5.2 (arm64):

| Scanner | Control | Result |
|---|---|---|
| **ClamAV 1.5.3**, signature set 28078 (355,577 signatures, same day) | EICAR detected | **0 detections** across 160 files |
| **Apple XProtect** 5353 — the 451-rule set macOS scans downloads with | a crafted file matches `XProtect_MACOS_71915a8`; a near-miss one condition short does not | **no threat-naming rule fired** |
| **Yara-Rules community set** — 12,685 rules from 436 files | (the set is deliberately trigger-happy, which is the control) | **no threat-naming rule fired**; 461 descriptive hits, below |
| **Gatekeeper** (`spctl -a -t execute`) | — | **rejected**, with and without a quarantine xattr |
| **`codesign -v`** | — | signature valid on disk; `codesign -d` reports the cdhash we computed by hand, for all five sample binaries |

The Gatekeeper result is the one to keep in view. The Mach-O is real enough that Apple's own
tooling parses it, validates its ad-hoc signature and agrees with our hand-computed cdhash —
and the operating system still refuses to run it as a download, exactly as it refuses any
ad-hoc-signed binary. Realistic to a forensic parser, refused by the actual security gate, is
the shape this project wants.

### The 461 community-YARA hits, itemised

None of them names a threat. They are *characteristic* rules — statements about what a file
contains — and a genuine artifact of the same kind fires them identically:

| Rule | Fires because |
|---|---|
| `domain`, `url`, `contains_base64` | the artifacts contain domain names and encoded strings, as they must |
| `IsPE64`, `IsConsole`, `HasOverlay` | the PEs are 64-bit console binaries with an overlay, which is true |
| `win_registry`, `win_files_operation`, `win_token`, `network_tcp_socket`, `Str_Win32_Winsock2_Library` | the import table names registry, file and winsock APIs, which is the point of having one |
| `with_sqlite` | the macOS databases are SQLite |
| `Big_Numbers1` | `Amcache.hve` contains long hex strings, which are the SHA1 `FileId`s a real Amcache also contains |
| `Browsers` | `Amcache.hve` mentions `chrome.exe`, one of the benign decoy names |
| `Misc_Suspicious_Strings` | a prefetch record for `CMD.EXE` contains the string `CMD.EXE` |
| `HasModified_DOS_Message` | *fired on the first run; since fixed — see below* |

`HasModified_DOS_Message` was the one hit that meant something. It fired on every PE because
the DOS header ran straight into the PE header with no stub at all — a fingerprint of the
generator rather than a property of the artifact. The canonical MSVC header and stub are now
reproduced byte for byte and the rule no longer fires.

Making a synthetic binary *less* distinguishable is a trade worth being explicit about. It is
the right one here because the thing being removed was an accident, not a disclosure: the
deliberate marking is the in-band `ARTIFACTFORGE` anchor, which every artifact still carries
and which Gate 3 still requires. Distinguishability that comes from an honest marker is a
safety property; distinguishability that comes from an incomplete header is just a bug that
happened to be load-bearing.

### VirusTotal

Not submitted, and not to be submitted.

Uploading a file to VirusTotal publishes it and its hash to a third party permanently, and
[`SECURITY.md`](../SECURITY.md) tells everyone else not to submit these hashes to a
threat-intelligence platform. Doing it ourselves to get a badge would be the same pollution
the policy exists to prevent — a synthetic SHA256 that acquires a reputation is a small piece
of noise in somebody else's data and it never goes away. ClamAV and XProtect run locally
against current signature sets and answer the question that actually mattered.

## What this does not protect against

Someone determined to build malware will not start from here — writing a functional payload
from scratch is far easier than adding one to a deterministic generator that fails its own
tests the moment you do. The realistic risk is not weaponisation, it is **confusion**: a
generated artifact escaping its context and being taken for real. That is what the in-band
markers, the RFC-reserved indicators and [`SECURITY.md`](../SECURITY.md) are for.
