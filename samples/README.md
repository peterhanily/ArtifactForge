# Samples

Three generated scenes are committed for inspection without running ArtifactForge.

> **Synthetic samples.** Nothing here was collected from a real host or incident. Do not
> submit these values to VirusTotal, a blocklist, a detection rule or a threat-intelligence
> platform. See [`../SECURITY.md`](../SECURITY.md) and
> [`../docs/inert-by-construction.md`](../docs/inert-by-construction.md).

| Sample | Family | Answer-bearing pivot |
| --- | --- | --- |
| [`01-windows-dropper`](01-windows-dropper/) | Windows | Five Amcache FileId SHA-1 values resolve to five resident PEs. Run, Prefetch and Chromium records provide separate context; Task XML and a Shell Link reference two other residents. |
| [`02-macos-quarantined-app`](02-macos-quarantined-app/) | macOS | Five serialized quarantine-xattr UUIDs resolve to five QuarantineEventsV2 rows. TCC, knowledgeC and LaunchAgent records add modeled context. |
| [`03-linux-autostart-history`](03-linux-autostart-history/) | Linux | One resident guest path is the unique intersection of three XDG Exec paths and three Bash-history command paths. |

Each directory contains:

- the loose artifacts;
- a generated `README.md` containing current parser observations; and
- `ARTIFACT_ANSWERS.json`, whose claims are re-derived from the committed bytes.

## Safety and scope

Gate 3 checks the emitted executable bodies: PE `.text` starts with `ret` and is otherwise
zero, Mach-O `__text` is `mov w0, #0; ret`, and ELF `.text` is the nine-byte direct-exit body
`xor edi,edi; mov eax,60; syscall`. The ELF interpreter would run before that entry on an
execution attempt. Do not execute the samples, run `ldd`, launch their configuration records
or evaluate the Bash history.

Classified structured artifacts carry an in-band `ARTIFACTFORGE` marker except for the strict
serialized quarantine-xattr profile. Task XML and Shell Link agreement proves serialized
configuration and reference relationships, not registration, activation or execution.

The SQLite files come from ArtifactForge's deterministic owned writer; `sqlite3` is a consumer
oracle. The Linux sample is generated from Fixture ABI v2, which binds logical guest modes.
This gallery commits only copied artifact bytes, not an activation-ready filesystem projection.

## Reproduce

From the repository root:

```sh
scripts/make-samples.sh
```

Windows and macOS use the published development-suite key. Linux uses
`examples/fixtures/linux-glibc-x86_64-loose-v2.json`. The public seeds and answers make these
scenes reproducible and unsuitable for performance scoring.

`tests/test_samples_gate.py` reopens every committed artifact with the declared readers,
re-derives the answer keys and checks that no private suite material was committed.
