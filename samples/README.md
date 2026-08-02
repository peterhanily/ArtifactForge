# Samples

Three generated scenes, committed so they can be read without running anything.

> **Everything in here is synthetic.** No file came from a real host. No hash, UUID, bundle
> identifier, URL or path identifies anything real, and none should be submitted to
> VirusTotal, a blocklist, a detection rule or a threat-intelligence platform. Every binary is
> payload-free under format-specific checks: PE `.text` starts with `ret` and is otherwise
> zero, Mach-O `__text` is `mov w0, #0; ret`, and ELF's sole executable segment is the
> nine-byte `xor edi,edi; mov eax,60; syscall` direct-exit body. The ELF interpreter means a
> real execution attempt would enter the dynamic loader first. Classified structured artifacts
> carry an in-band `ARTIFACTFORGE`
> marker; serialized quarantine-xattr sidecars do not. See [`../SECURITY.md`](../SECURITY.md) and
> [`../docs/inert-by-construction.md`](../docs/inert-by-construction.md).

| Sample | Family | What it holds |
|---|---|---|
| [`01-windows-dropper`](01-windows-dropper/) | Windows | Five PEs, a Run key with three autostarts, eight Amcache records and four prefetch files. Persistence names one binary; Amcache's hashes match a different one; one execution record names a program that is gone. |
| [`02-macos-quarantined-app`](02-macos-quarantined-app/) | macOS | Five signed arm64 Mach-O binaries with quarantine records, a TCC database with grants and refusals, knowledgeC usage, and LaunchAgent plists. One app was allowed *and* used; everything else about it hangs off its quarantine UUID. |
| [`03-linux-autostart-history`](03-linux-autostart-history/) | Linux | Five nested ELF64 x86-64 files, three XDG autostart records and one timestamped Bash history. One resident path is named by both text artifacts; neither record proves activation or execution. |

Each directory holds the artifacts, a `README.md` with declared parser output pasted in —
including LIEF/pyelftools, PyXDG/raw and dissect.target/raw for Linux — and an
`ARTIFACT_ANSWERS.json` answer key.

The committed macOS databases were written with **sqlite3 3.50.4**. A SQLite header embeds the
version of the library that wrote it, so rebuilding them elsewhere produces different bytes in
those three files and in nothing else — measured against a Linux/x86-64 rebuild with 3.53.1,
where every PE, Mach-O, registry hive, prefetch record, plist and answer key was byte-identical
to the macOS/arm64 originals. The Linux fixture is standard-library generated and does not add
another environment-dependent database format.

The Windows and macOS samples are built from a **dev suite**, whose key is published in
`artifactforge/suite.py` on purpose. The Linux sample is built from the public
`examples/fixtures/linux-glibc-x86_64-loose-v1.json` Fixture Core recipe. That is what makes
all three reproducible: `scripts/make-samples.sh` regenerates these exact bytes, and a
regeneration that differs means the generator changed. Their seeds, joins and answers are
public, so all three are trivially cheatable and useless as a score — for a Windows/macOS
benchmark corpus, mint a hold-out suite:

```sh
artifactforge bench new suite --n 100 --kind holdout
```

The Linux sample is generator-assurance and fixture material only; it never enters Gate 4.
Fixture ABI v1 binds paths, sizes and hashes but not POSIX modes, and deterministic release
archives normalize artifact files to 0644. The ELF files are therefore valid executable-format
evidence, not an activation-ready filesystem. Do not execute them, use `ldd`, launch their XDG
records, or source/evaluate their Bash history.

`tests/test_samples_gate.py` re-reads every committed file with the real parsers on every test
run, re-derives the answer key from the bytes as committed, and checks that nothing private
was committed alongside them.
