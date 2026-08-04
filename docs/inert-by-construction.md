# Inert by construction

ArtifactForge generates executable-shaped and persistence-shaped synthetic files for responder
training. Those files can be confused with real evidence if they escape their intended context.
This document defines "inert" for the emitted profiles and identifies the tests that enforce
that definition.

## The rule

A generated binary reproduces the forensic **signal** and never the offensive **capability**.

It has a real import table, symbol table, content or structural hashes, and signing structures
for responder tools to inspect. It has no payload, network code, shell, self-persistence
mechanism or decryption routine.

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
external loader/dependency code runs first. That code is outside the emitted main-object claim.
ArtifactForge never executes the ELF or invokes `ldd`.

The fixed DOS stub reproduces the conventional compiler-generated message-and-exit profile byte
for byte. Because it is executable, Gate 3 requires exact equality with the canonical bytes.
`tests/test_gate_mutations.py` overwrites four bytes of it and requires the gate to reject the
mutation.

## Reference and configuration files are never activated

Windows scenes now also contain a Task Scheduler XML definition and a Shell Link. They carry
no executable code, but that alone would not make them safe to activate, so their closed
profiles remove the activation surfaces and the generator never performs the activation step.

The task is serialized UTF-16LE configuration with no triggers or principal. `Enabled` and
`AllowStartOnDemand` are false and its sole `Exec` action has one allowlisted resident PE path,
with no arguments or working directory. ArtifactForge never registers it or runs its command.
The Windows-native canary assigns the XML only to an unregistered in-memory definition through
`TaskService.Connect`, `NewTask(0)` and `TaskDefinition.XmlText`.

The Shell Link is a local-file reference with no ID list, network target, arguments, working
directory, relative path, icon, environment data or ExtraData. ArtifactForge never resolves or
follows the target. Its Windows-native canary opens the private-copy link only with
`WScript.Shell.CreateShortcut` and never calls `Save`, `Resolve` or `Run`. Those canaries are
inspection designs, not activation tests, and their first hosted Windows observation remains
pending. Portable parsing and byte-bound joins therefore support only configuration/reference
claims, not task registration, shortcut activation or target execution.

Prefetch records are compressed metadata, not executable content. Current scenes use a
bounded MAM algorithm-4 v30 variant with one metric and volume. The first-party expected-size
reader owns exact compressed framing and inner layout; `pyscca` acceptance plus typed
`pyscca`/Dissect agreement covers the external semantic view. Dissect's EOF-driven output is
not an exact-size oracle. The Windows `RtlDecompressBufferEx` canary only decompresses a
private copy and compares MAM's declared output with the portable reader; it neither launches
the named program nor claims consumption of post-size bits, and its first hosted result remains
pending.

## Why the Mach-O is ad-hoc signed

The ad-hoc CodeDirectory gives the file the signing structures and `cdhash` that forensic tools
inspect. To keep those bytes deterministic, the signature is computed in-process rather than
applied afterwards. Gate 3 then statically binds `LC_MAIN`, the executable mappings, the exact
two-instruction body and the CodeDirectory coverage boundary.

That is a static emitted-file claim. ArtifactForge does not execute the Mach-O, and neither
parser acceptance nor `codesign` validation proves that a particular macOS loader reaches the
entry or that the resulting process returns zero. Treat it as executable-shaped loose
evidence, keep the marker and disclosure with it, and do not execute it.

## Marked in-band, with one bounded serialized-value exception

A bundle can be renamed and a README can be lost. The only disclosure that survives a file
being copied somewhere else is one inside the bytes, so every classified structured format
carries an `ARTIFACTFORGE` anchor that `strings` finds:

| Format | Where |
|---|---|
| PE | overlay: `ARTIFACTFORGE-SYNTHETIC-<16 hex>` |
| Mach-O | `__TEXT,__cstring`: `ARTIFACTFORGE-SYNTHETIC-<16 hex>` |
| ELF | `.note.artifactforge`: `ARTIFACTFORGE-SYNTHETIC-<16 hex>` |
| Registry hive | a root `artifactforge_synthetic` key with UTF-16 marker and notice values |
| Prefetch | a reserved v30 filename-strings entry sharing the modeled volume token |
| Task Scheduler XML | UTF-16 description and owned URI containing `ARTIFACTFORGE` |
| Shell Link | Unicode display name ending in `[ARTIFACTFORGE SYNTHETIC]` |
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

The disclosure text is plain ASCII. A binary plist re-encodes any string containing a non-ASCII
character as UTF-16, which would hide the anchor from `strings`. ASCII keeps the marker visible
in every emitted container.

## Indicators point nowhere real

No generated artifact may name a real external indicator. Domains are RFC 2606 reserved
(`.example`, `.invalid`, `.test`); addresses are RFC 5737 / RFC 3849 documentation ranges or
RFC 1918 private ones; and no bundle identifier may sit under a real vendor's reverse-DNS
prefix. On macOS the identifier is embedded in the code signature, so a synthetic binary must
not assert a real vendor identity such as `com.apple.Notes`. Windows executable *filenames* are
not policed because a common filename such as `chrome.exe` does not assert producer identity.
Gate 3 scans every emitted artifact for URLs and addresses and rejects values outside the
allowed ranges. The check applies to emitted bytes, not only to generator input pools.

## Enforced properties

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
| Task XML is disabled, trigger-free and argument-free | Gate 1's `scheduled-task-xml-profile`; Gate 3 checks only its marker |
| Shell Link has no activation-related optional surfaces or trailing data | Gate 1's `shell-link-profile`; Gate 3 checks only its marker |
| A marker-eligible format with no declared marker fails | same; an unknown format is a failure, not a skip |
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

Each mutation test breaks one declared property and requires the corresponding gate to turn
red. This establishes that the gate observes the property it reports.

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
arithmetic. The schema is
[`../scanner-attestation.schema.json`](../scanner-attestation.schema.json), with scanner-specific
fail-closed rules in `scripts/scanner_attestation.py`.

The record carries four required result slots. The current loose-file profile can satisfy the
three signature-scanner rules below, but it deliberately cannot produce an all-green record:
Apple documents `spctl` assessment for top-level application bundles, while ArtifactForge
currently emits loose Mach-O files. Gatekeeper therefore remains an explicit red/inapplicable
slot until the app-bundle phase supplies a bound bundle target and bundle-shaped control.

| Result | Required control and coverage |
|---|---|
| **ClamAV** | engine and signature versions; EICAR must be detected; ClamAV's own `Scanned files` count must equal the bound corpus count |
| **XProtect YARA** | yara-python version and exact XProtect-rule-file fingerprint; the selected `XProtect_MACOS_71915a8` rule must match its harmless positive input and reject a one-condition near miss; every corpus file is scanned |
| **Community YARA** | yara-python version and an exact manifest fingerprint of every selected rule file; a synthetic hit/near-miss controls the **engine only**; selected/loaded/failed rule-file accounting separately proves coverage, and any compile failure or rule match is red |
| **Gatekeeper** | currently red/inapplicable: no `spctl` process is run over a loose Mach-O and the checker rejects any fabricated successful loose-file observation; a future success profile requires descriptor-bound top-level `.app` target and control bundles |

The community control is intentionally not described as exercising the community corpus. It
proves that the engine can compile and match a rule. The rule manifest, compile accounting and
per-file scan coverage answer the separate question of what community rules actually loaded.
Every match is red. A rule name is not a trustworthy severity policy: an arbitrary supplied
corpus can call a rule `domain`, `keylogger`, or anything else, so the attester has no global
name allowlist that can silently downgrade it. Per-file filename, relative path, extension,
file type and MD5 externals are populated when the selected rules declare them. Transitive
YARA includes are rejected because bytes outside the selected rule manifest would otherwise
change compiled semantics without changing its fingerprint.

Compilation is bounded by the 4 MiB-per-file/128 MiB-total rule-source capture policy, but it
still runs in-process and outside the 600-second corpus-match deadline. A compiler exception is
red; a pathological compiler/rule can still hang or exhaust this process until the hostile-
validation phase moves compilation behind an OS-enforced worker boundary.

Gatekeeper is a host policy observation, not a malware-signature scan. Apple's
[TN2206](https://developer.apple.com/library/archive/technotes/tn2206/_index.html) says `spctl`
must be run only on top-level app bundles; a loose platform binary is therefore not a
valid positive control, and a non-zero loose-target result cannot prove policy rejection. The
separate `macos-native` CI attestation covers platform parsing and signing checks; it does not
substitute for a bundle-shaped Gatekeeper observation. App-bundle capture and policy assessment
are deferred to the declared app-bundle coverage phase.

Earlier prose quoted a 2026-07-31 scan without an exact corpus manifest/digest, complete argv,
error/exclusion accounting, a real community-YARA control or a Gatekeeper acceptance control.
Those numbers are not attested results and should not be quoted as controlled scanner evidence.
Its Gatekeeper output is inconclusive rather than rejection evidence. A later unbound strict
local diagnostic was also red, with community-YARA matches and rule-file load failures. It is
not a clean attestation or a calibrated malware conclusion.

The dated Phase 6B and Phase 6C checkpoints are maintained in
[`SECURITY.md`](../SECURITY.md#scanner-claims-require-an-attestation). The latest Phase 6C
record is red overall. Its ClamAV and XProtect slots are complete controlled observations, but
Gatekeeper is inapplicable to the loose-Mach-O profile and community YARA did not establish
complete coverage. The local JSON is self-reported and unsigned; it binds its stated inputs and
observations but does not authenticate the host or scanner executables.

### VirusTotal

Not submitted, and not to be submitted.

Uploading a file to VirusTotal publishes it and its hash to a third party permanently, and
[`SECURITY.md`](../SECURITY.md) tells everyone else not to submit these hashes to a
threat-intelligence platform. Uploading them would permanently pollute a third-party dataset
with synthetic indicators. The attestation workflow is local and does not upload corpus bytes
or digests.

## What this does not protect against

These gates establish properties only for the exact emitted profiles. They do not establish
that an arbitrary fork or modified generator is safe. The primary distribution risk is
**confusion**: a generated artifact may escape its context and be treated as real evidence.
In-band markers, reserved indicators and [`SECURITY.md`](../SECURITY.md) reduce that risk.
