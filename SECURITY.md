# Security policy

ArtifactForge generates **synthetic forensic artifacts** — binaries, registry hives, prefetch
records and macOS databases — for training and evaluation. It ships no service and listens on
no port. Fixture commands do parse caller-supplied local JSON and filesystem trees, so those
boundaries are treated as untrusted. The security surface is unusual, and this file says what
we actually care about.

## Report privately

**security@peterhanily.com** — please do not open a public issue for either of the first two
categories below.

## What we want to hear about

1. **A shipped binary is not inert, or its synthetic marking can be stripped.**

   Every generated binary reproduces the forensic *signal* — a real import table, a real
   symbol table, and real content or structural hashes — without a payload. The PE's `.text`
   section is a single `ret` followed by zero padding; the Mach-O writer emits an eight-byte
   `__text` containing `mov w0, #0 ; ret`. Gate 3 parses and bounds-checks both formats. For
   PE it binds `AddressOfEntryPoint` to the sole executable `.text` section, admits only the
   modeled system DLL imports, and rejects every data directory except imports—including TLS
   and managed-code startup. For Mach-O it binds `LC_MAIN` to the sole executable instruction
   section, admits only the writer's system-library/load-command/section profile, rejects
   alternate startup mechanisms, and verifies that the CodeDirectory page hashes cover every
   byte before the signature. Parseable mutations of each property are required to turn the
   gate red.

   The Mach-O is a genuinely loadable, ad-hoc-signed arm64 executable, because an unsigned one
   is not loadable at all and would therefore not be a realistic artifact. It runs and returns
   zero. The fixed 16-bit DOS stub only prints its conventional message and exits. If you can
   make anything this project emits execute native code beyond those fixed return/print stubs,
   perform file, network, persistence or process operations, or carry a usable secret, that is
   a bug and we want it before anyone else does. See
   [`docs/inert-by-construction.md`](docs/inert-by-construction.md).

2. **A generated artifact could be mistaken for genuine evidence, or an indicator points at
   something real.**

   Every parser-classified structured format carries an in-band `ARTIFACTFORGE` anchor so a
   file that escapes its bundle is still recognisable as generated. Plain sidecars are outside
   that gate: in particular, the serialized `com.apple.quarantine` value has no in-band marker.
   Domains must be RFC 2606 reserved (`.example`, `.invalid`, `.test`) and addresses RFC 5737 /
   RFC 3849 or RFC 1918. If you find a classified format shipping without a marker, a marker
   that a normal workflow strips, or an indicator naming something that could plausibly be a
   real host, domain, bundle identifier or signing authority — tell us.

3. Anything else: a normal public issue is fine.

## What this project is not

It is **not threat intelligence**, and its output is **not evidence**.

Nothing here was observed anywhere. Every hash, UUID, bundle identifier, URL, path and
timestamp is fabricated by a deterministic function of a seed. Do not submit them to
VirusTotal, a blocklist, a detection rule, a SIEM watchlist, or a threat-intelligence
platform. A synthetic SHA256 that acquires a reputation is a small piece of pollution in
somebody else's data, and it never goes away.

Artifacts are generated for training a responder or evaluating an agent, and they belong in
that context. If you publish results from them, say they are synthetic.

## Scanner claims require an attestation

A terminal line saying "0 detections" is not a publishable result. Local scanner observations
must be produced by `scripts/scan-exposure.sh --output <record.json>` and must pass
`scripts/scan-exposure.sh --check <record.json>`. The record format is
[`scanner-attestation.schema.json`](scanner-attestation.schema.json); its stricter semantic
checks live in `scripts/scanner_attestation.py` and are mutation-tested without requiring
ClamAV or macOS tools on the default Linux test host.

The checker fails closed unless the record is at most 30 days old and contains all required
scanner results. Each result must identify the engine and rule version or fingerprint, bind to
the exact file manifest and corpus SHA256, record its UTC timestamp and command/method, pass an
applicable positive control, account for exclusions and errors, and state what the observation
does not prove. A missing scanner, failed control, partially loaded rule corpus, scan error,
unbound input, scanner or YARA-rule match, stale record or incompatible schema is a failure,
never a skip.

These scans are local. Producing an attestation does not relax the VirusTotal or
threat-intelligence prohibition above, and even a fresh clean attestation is only evidence
about exact bytes against dated signature snapshots — not proof of safety or inertness. The
record is self-reported and unsigned, so it also does not independently authenticate the scan
host or scanner executables.

## Fixture filesystem boundary

Fixture Core treats recipes, manifests and existing fixture trees as untrusted input. Strict
JSON loading rejects duplicate keys, unknown fields, non-normalised strings and floats.
Artifact inventory rejects absolute or traversing paths, symbolic links, special files and
case-fold collisions. Build and release refuse any pre-existing destination, stage beside the
destination, and use atomic no-replace publication only after regeneration or archive readback.
Verification pins the opened root and payload directories, snapshots only through held
descriptors, and rejects identity changes. Build syncs the complete generated tree before the
rename; if the final parent sync fails, the API and CLI explicitly report that the verified
output was published but its crash durability is uncertain.

Release uses a single descriptor-pinned fixture snapshot for reproduction and encoding, keeps
the temporary archive inode open through mode-setting, sync and post-write verification, and
checks that the published hard link names that inode. Archive verification independently
regenerates the embedded recipe; manifest-consistent but non-reproducible payloads are rejected.
Post-link directory-sync failure is reported as a published, verified archive with uncertain
crash durability rather than being ambiguously deleted.

The manifest is an integrity and reproducibility record, not a signature. Its seed and content
digests are public, and `benchmark_eligible` is permanently false: copying a fixture manifest
into a benchmark scenario would disclose the content answers the benchmark is meant to hide.
See [`docs/fixture-core.md`](docs/fixture-core.md).

## Scope

In scope: the generated artifacts, the generator, Fixture Core's parser/filesystem/archive
boundary, the benchmark's answer-key isolation, and the disclosure mechanisms above.

Out of scope: the DFIR parsers used as CI oracles — report those to their own maintainers — and
EvidenceForge. It is not a declared dependency; isolated contract jobs install it and one test
temporarily monkeypatches an imported private method in memory. Nothing that ships modifies an
EvidenceForge source tree, branch or repository.
