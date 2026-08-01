# Samples

Two generated scenes, committed so they can be read without running anything.

> **Everything in here is synthetic.** No file came from a real host. No hash, UUID, bundle
> identifier, URL or path identifies anything real, and none should be submitted to
> VirusTotal, a blocklist, a detection rule or a threat-intelligence platform. Every binary is
> inert — its entire code section is a single return instruction — and carries an in-band
> `ARTIFACTFORGE` marker. See [`../SECURITY.md`](../SECURITY.md) and
> [`../docs/inert-by-construction.md`](../docs/inert-by-construction.md).

| Sample | Family | What it holds |
|---|---|---|
| [`01-windows-dropper`](01-windows-dropper/) | Windows | Five PEs, a Run key with three autostarts, eight Amcache records and four prefetch files. Persistence names one binary; Amcache's hashes match a different one; one execution record names a program that is gone. |
| [`02-macos-quarantined-app`](02-macos-quarantined-app/) | macOS | Five signed arm64 Mach-O binaries with quarantine records, a TCC database with grants and refusals, knowledgeC usage, and LaunchAgent plists. One app was allowed *and* used; everything else about it hangs off its quarantine UUID. |

Each directory holds the artifacts, a `README.md` with real parser output pasted in — pefile,
regipy, libscca, LIEF, sqlite3, plistlib — and a `ARTIFACT_ANSWERS.json` answer key.

The committed macOS databases were written with **sqlite3 3.50.4**. A SQLite header embeds the
version of the library that wrote it, so rebuilding them elsewhere produces different bytes in
those three files and in nothing else — measured against a Linux/x86-64 rebuild with 3.53.1,
where every PE, Mach-O, registry hive, prefetch record, plist and answer key was byte-identical
to the macOS/arm64 originals.

These are built from a **dev suite**, whose key is published in `artifactforge/suite.py` on
purpose. That is what makes them reproducible: `scripts/make-samples.sh` regenerates these
exact bytes, and a regeneration that differs means the generator changed. It also means they
are trivially cheatable and useless as a score — for that, mint a hold-out suite:

```sh
artifactforge bench new suite --n 100 --kind holdout
```

`tests/test_samples_gate.py` re-reads every committed file with the real parsers on every test
run, re-derives the answer key from the bytes as committed, and checks that nothing private
was committed alongside them.
