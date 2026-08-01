# Security policy

ArtifactForge generates **synthetic forensic artifacts** — binaries, registry hives, prefetch
records and macOS databases — for training and evaluation. It ships no service, listens on no
port, and processes no untrusted input. The security surface is therefore unusual, and this
file says what we actually care about.

## Report privately

**security@peterhanily.com** — please do not open a public issue for either of the first two
categories below.

## What we want to hear about

1. **A shipped binary is not inert, or its synthetic marking can be stripped.**

   Every generated binary reproduces the forensic *signal* — a real import table, a real
   symbol table, and real content or structural hashes — without a payload. The PE's `.text`
   section is a single `ret` followed by zero padding; the Mach-O writer emits an eight-byte
   `__text` containing `mov w0, #0 ; ret`. Gate 3 parses and bounds-checks PE `.text`; its
   current Mach-O check recognizes the permitted byte sequence but does not independently
   enumerate every executable section.

   The Mach-O is a genuinely loadable, ad-hoc-signed arm64 executable, because an unsigned one
   is not loadable at all and would therefore not be a realistic artifact. It runs and returns
   zero. If you can make anything this project emits do more than that — execute, connect,
   read, write, or carry a usable secret — that is a bug and we want it before anyone else
   does. See [`docs/inert-by-construction.md`](docs/inert-by-construction.md).

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

## Scope

In scope: the generated artifacts, the generator, the benchmark's answer-key isolation, and
the disclosure mechanisms above.

Out of scope: the DFIR parsers used as CI oracles — report those to their own maintainers — and
EvidenceForge. It is not a declared dependency; isolated contract jobs install it and one test
temporarily monkeypatches an imported private method in memory. Nothing that ships modifies an
EvidenceForge source tree, branch or repository.
