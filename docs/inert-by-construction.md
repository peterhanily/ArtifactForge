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

Concretely, the generated native code regions are:

| Format | Region | Code | Bytes |
|---|---|---|---|
| PE (x86-64) | `.text` | `ret` | `C3` |
| PE (16-bit) | MS-DOS stub | print a sentence, exit | `0E 1F BA 0E 00 B4 09 CD 21 B8 01 4C CD 21` |
| Mach-O (arm64) | `__text` | `mov w0, #0 ; ret` | `00 00 80 52  C0 03 5F D6` |
| ELF (x86-64) | sole RX `.text`/`PT_LOAD` | `xor edi,edi ; mov eax,60 ; syscall` | `31 FF B8 3C 00 00 00 0F 05` |

PE `.text` contains zero padding after its return; Mach-O `__text` is exactly the two listed
instructions. Gate 3 reads what actually lands on disk. Its PE check parses `.text` and rejects
non-zero bytes after `ret`; its Mach-O check parses the load commands and sections, binds
`LC_MAIN` to the start of the sole executable instruction section, rejects alternate entry
points, and permits only zero padding after the two instructions. It also recomputes every
CodeDirectory page hash and requires coverage to end exactly where `LC_CODE_SIGNATURE` begins.
The PE check independently pins the complete DOS header/stub profile, sole executable section,
entry point, import-only data-directory profile and modeled system DLL set. The Mach-O check
likewise fixes the allowed load commands, segment protections, section types and Apple system
libraries, so initializer tables and alternate pre-main mechanisms are red.

The ELF check independently requires the exact 8,784-byte main-object layout, one nine-byte
RX load at the entry, non-overlapping R/RX/RW file and virtual ranges, zero-only unclaimed
slack, an RW/NX stack, RELRO and a five-tag dynamic allowlist. The main object has no imported
callable symbol or alternate entry surface. This is not a claim that an execution attempt runs
only those nine bytes: the file declares `/lib64/ld-linux-x86-64.so.2` and `libc.so.6`, so
external loader/dependency code—which is outside the emitted main-object claim—runs first.
ArtifactForge never executes the ELF or invokes `ldd`.

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

## Marked in-band, with one bounded serialized-value exception

A bundle can be renamed and a README can be lost. The only disclosure that survives a file
being copied somewhere else is one inside the bytes, so every classified structured format
carries an `ARTIFACTFORGE` anchor that `strings` finds:

| Format | Where |
|---|---|
| PE | overlay: `ARTIFACTFORGE-SYNTHETIC-<16 hex>` |
| Mach-O | `__TEXT,__cstring`: `ARTIFACTFORGE-SYNTHETIC-<16 hex>` |
| ELF | `.note.artifactforge`: `ARTIFACTFORGE-SYNTHETIC-<16 hex>` |
| Registry hive | the base block's hive name, `ArtifactForgeHive` (UTF-16) |
| Prefetch | a reserved filename-strings entry |
| SQLite (knowledgeC, TCC, QuarantineEventsV2) | a reserved `artifactforge_synthetic` table |
| Binary plist | a reserved `artifactforge_synthetic` key |
| XDG desktop entry | `X-ArtifactForge-Synthetic=ARTIFACTFORGE` |
| Bash history | exact first record `: 'ARTIFACTFORGE-SYNTHETIC-LINUX'` |
| Serialized quarantine xattr | no extension field exists; strict-valid non-executable values are explicitly exempt |

The serialized `com.apple.quarantine` value is a parser-classified loose representation, not
an extended attribute applied to host metadata, and it does not carry an anchor. Its complete
real four-field grammar has no extension field for one. Gate 1 snapshots it and requires two
independently implemented first-party readers to agree type-for-type before checking the exact
flags, lowercase hexadecimal timestamp, bounded ASCII agent and uppercase RFC 4122 v4 UUID
profile. Gate 3 exempts only bytes accepted by that strict parser as non-executable serialized
data. A newline, padding, extra field, noncanonical value or arbitrary file that merely uses
the suffix is red rather than silently exempt.

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

The generator-level safety and marking claims above map to the checks below. The table states
their present scope rather than treating a weaker check as proof of a stronger property:

| Property | Enforced by |
|---|---|
| PE entry point reaches the sole executable `.text`, containing one `ret` and padding | `gates/inertness.py::_pe_code_is_inert` |
| The PE's MS-DOS stub is the canonical one, byte for byte | same |
| `LC_MAIN` reaches only `mov w0,#0 ; ret` and zero padding | `gates/inertness.py::_macho_code_is_inert` |
| The Mach-O CodeDirectory covers every byte before its bounded signature region | `gates/inertness.py::_verify_macho_signature` |
| The ELF main-object entry reaches only the exact nine-byte direct-exit RX load | `gates/inertness.py::_elf_code_is_inert` |
| ELF file/virtual loads do not overlap and every unclaimed byte is zero | same |
| Every marker-eligible classified structured format carries its marker | `gates/inertness.py::run`, `MARKERS` table |
| A marker-eligible format with no declared marker fails | same — an unknown format is a failure, not a skip |
| Only a strict-valid serialized quarantine xattr is exempt from the marker requirement | `gates/inertness.py::run`, `_MARKER_EXEMPT_FORMATS` |
| No URL outside RFC 2606 | `gates/inertness.py::_indicator_hygiene` |
| No address outside RFC 5737 / RFC 1918 | same |
| No bundle identifier under a real vendor's prefix | same, `_REAL_VENDOR_PREFIXES` |
| Stripping a marker turns Gate 3 red | `tests/test_gate_mutations.py::test_inertness_reddens_when_the_synthetic_marker_is_stripped` |
| Code past the `ret` turns Gate 3 red | `tests/test_gate_mutations.py::test_inertness_reddens_when_the_code_section_is_not_inert` |
| Moving the PE entry point past `ret` turns Gate 3 red | `tests/test_gate_mutations.py::test_inertness_reddens_when_pe_entry_point_skips_ret` |
| Replacing a modeled system DLL import with an arbitrary load-before-entry DLL turns Gate 3 red | `tests/test_gate_mutations.py::test_inertness_reddens_when_pe_imports_an_unmodeled_dll` |
| Moving Mach-O `LC_MAIN`, changing its exit instruction, or shortening signature coverage turns Gate 3 red | the three `test_inertness_reddens_when_macho_*` mutations |
| Reclassifying the Mach-O GOT as a pre-main initializer table turns Gate 3 red after signature repair | `tests/test_gate_mutations.py::test_inertness_reddens_when_macho_got_becomes_an_initializer_table` |
| Changing ELF structure, hiding bytes in slack, overlapping virtual loads or changing file size turns Gate 3 red | the `test_independent_elf_safety_parser_rejects_*` mutations in `tests/test_linux_scene.py` |
| Moving the ELF entry or changing its instruction bytes turns the exact Gate 1 profile red | the `test_parseable_elf_*` mutations in `tests/test_linux_validity.py` |
| Changing the exact Bash marker/row shape or XDG field bounds turns Gate 1 red | `test_bash_parsers_accept_but_exact_linux_scene_profile_rejects_history_shape_mutations` and `test_xdg_parser_valid_utf8_value_overflow_fails_exact_profile` |
| Tampering with the DOS stub turns Gate 3 red | `tests/test_gate_mutations.py::test_inertness_reddens_when_the_dos_stub_is_tampered_with` |
| Redirecting the DOS entry registers while retaining the familiar message bytes turns Gate 3 red | `tests/test_gate_mutations.py::test_inertness_reddens_when_dos_entry_registers_change` |
| A routable domain turns Gate 3 red | `tests/test_gate_mutations.py::test_inertness_reddens_when_an_indicator_could_be_real` |
| A real vendor's bundle id turns Gate 3 red | `tests/test_gate_mutations.py::test_inertness_reddens_when_a_bundle_id_names_a_real_vendor` |

The mutation tests are the load-bearing ones. A gate that has never been observed to fail
proves nothing, so each of these breaks the property on purpose and requires the gate to
notice.

## What real scanners make of it

Scanner claims now require a machine-readable attestation. Run the full local workflow with a
community-rule checkout and an explicit output path:

```sh
YARA_RULES=/path/to/Yara-Rules/rules \
  scripts/scan-exposure.sh --output scanner-attestation.json
scripts/scan-exposure.sh --check scanner-attestation.json
```

Pass `--corpus DIR` to check mode when the scanned corpus is still available; that recomputes
every file digest and the canonical corpus-tree SHA256. Without the live directory, check mode
still validates the record's internally bound file manifest, controls, coverage, timestamps and
arithmetic. The schema is [`../scanner-attestation.schema.json`](../scanner-attestation.schema.json),
with scanner-specific fail-closed rules in `scripts/scanner_attestation.py`.

One record is valid only when all four required observations meet their own evidence rule:

| Result | Required control and coverage |
|---|---|
| **ClamAV** | engine and signature versions; EICAR must be detected; ClamAV's own `Scanned files` count must equal the bound corpus count |
| **XProtect YARA** | yara-python version and exact XProtect-rule-file fingerprint; the selected `XProtect_MACOS_71915a8` rule must match its harmless positive input and reject a one-condition near miss; every corpus file is scanned |
| **Community YARA** | yara-python version and an exact manifest fingerprint of every selected rule file; a synthetic hit/near-miss controls the **engine only**; selected/loaded/failed rule-file accounting separately proves coverage, and any compile failure or rule match is red |
| **Gatekeeper** | `spctl`/macOS policy version; a known host platform binary must first be accepted; `codesign -v` must validate the selected manifest-bound Mach-O; the target result must be an explicit rejection |

The community control is intentionally not described as exercising the community corpus. It
proves that the engine can compile and match a rule. The rule manifest, compile accounting and
per-file scan coverage answer the separate question of what community rules actually loaded.
Every match is red. A rule name is not a trustworthy severity policy: an arbitrary supplied
corpus can call a rule `domain`, `keylogger`, or anything else, so the attester has no global
name allowlist that can silently downgrade it. Per-file filename, relative path, extension,
file type and MD5 externals are populated when the selected rules declare them. Transitive
YARA includes are rejected because bytes outside the selected rule manifest would otherwise
change compiled semantics without changing its fingerprint.

The Gatekeeper entry is explicitly a single-target, single-host observation, not a whole-corpus
scan or portable policy guarantee. A non-zero `spctl` exit without the acceptance control and
an explicit `rejected` result is an error, not evidence of rejection. The separate
`macos-native` CI attestation covers platform parsing and signing checks; it does not substitute
for this dated scanner attestation.

Earlier prose quoted a 2026-07-31 scan without an exact corpus manifest/digest, complete argv,
error/exclusion accounting, a real community-YARA control or a Gatekeeper acceptance control.
Those numbers are therefore not carried forward as attested results and should not be quoted as
controlled scanner evidence. No replacement record is fabricated here: a publishable result
starts with a complete run on the host that actually has all four required scanners and rules.
The resulting JSON is self-reported and unsigned; it binds the stated inputs and observations
but does not independently authenticate that host or its scanner executables.

### VirusTotal

Not submitted, and not to be submitted.

Uploading a file to VirusTotal publishes it and its hash to a third party permanently, and
[`SECURITY.md`](../SECURITY.md) tells everyone else not to submit these hashes to a
threat-intelligence platform. Doing it ourselves to get a badge would be the same pollution
the policy exists to prevent — a synthetic SHA256 that acquires a reputation is a small piece
of noise in somebody else's data and it never goes away. The attestation workflow is local and
does not upload corpus bytes or digests anywhere.

## What this does not protect against

Someone determined to build malware will not start from here — writing a functional payload
from scratch is far easier than adding one to a deterministic generator that fails its own
tests the moment you do. The realistic risk is not weaponisation, it is **confusion**: a
generated artifact escaping its context and being taken for real. That is what the in-band
markers, the RFC-reserved indicators and [`SECURITY.md`](../SECURITY.md) are for.
