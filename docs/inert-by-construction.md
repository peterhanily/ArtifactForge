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

| Format | Code section | Bytes |
|---|---|---|
| PE (x86-64) | `ret` | `C3` |
| Mach-O (arm64) | `mov w0, #0 ; ret` | `52 80 00 00  D6 5F 03 C0` |

Everything after that is zero padding. Gate 3 disassembles what actually lands on disk and
fails if a single instruction appears past the return.

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
RFC 1918 private ones. Gate 3 scans the emitted bytes of every artifact for URLs and addresses
and fails on anything outside those ranges — so this is enforced against the file, not against
the pool the file was drawn from.

## Checkable, not asserted

Every claim above is a test. These are the ones that would go red:

| Property | Enforced by |
|---|---|
| The PE's `.text` is one `ret` and padding | `gates/inertness.py::_pe_code_is_inert` |
| The Mach-O's `__text` is `mov w0,#0 ; ret` | `gates/inertness.py::_macho_code_is_inert` |
| Every emitted format carries its marker | `gates/inertness.py::run`, `MARKERS` table |
| A format with no declared marker fails | same — an unknown format is a failure, not a skip |
| No URL outside RFC 2606 | `gates/inertness.py::_indicator_hygiene` |
| No address outside RFC 5737 / RFC 1918 | same |
| Stripping a marker turns Gate 3 red | `tests/test_gate_mutations.py::test_inertness_reddens_when_the_synthetic_marker_is_stripped` |
| Code past the `ret` turns Gate 3 red | `tests/test_gate_mutations.py::test_inertness_reddens_when_the_code_section_is_not_inert` |
| A routable domain turns Gate 3 red | `tests/test_gate_mutations.py::test_inertness_reddens_when_an_indicator_could_be_real` |

The mutation tests are the load-bearing ones. A gate that has never been observed to fail
proves nothing, so each of these breaks the property on purpose and requires the gate to
notice.

## What this does not protect against

Someone determined to build malware will not start from here — writing a functional payload
from scratch is far easier than adding one to a deterministic generator that fails its own
tests the moment you do. The realistic risk is not weaponisation, it is **confusion**: a
generated artifact escaping its context and being taken for real. That is what the in-band
markers, the RFC-reserved indicators and [`SECURITY.md`](../SECURITY.md) are for.
