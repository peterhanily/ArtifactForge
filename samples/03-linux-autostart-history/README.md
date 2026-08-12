# Linux: one resident named by XDG autostart and Bash history

> **Synthetic sample.** Nothing here was collected from a real host or incident. Do not submit these values to a blocklist or threat-intelligence platform. See [`../../SECURITY.md`](../../SECURITY.md).

## Scenario

Five nested ELF files are resident. Three XDG autostart records name one set of three paths; a timestamped Bash history names another set of three. Their unique shared path identifies the subject, and that exact guest path maps to one recursive served path whose SHA-256 is computed from the committed ELF bytes.

## Scope

This is naming evidence, not activation evidence. Fixture ABI v2 binds logical guest modes, but this gallery contains only the copied artifact bytes and is not an activation-ready filesystem. Each ELF declares the glibc loader and `libc.so.6`; the loader would run before the nine-byte direct-exit entry. Do not execute the files, run `ldd`, launch the desktop entries or evaluate the history.

## Reproduce

From the repository root, run `scripts/make-samples.sh`. A byte difference means the generator or its declared inputs changed.

## Reader results

### ELF files: LIEF and pyelftools

Both readers report interpreter `/lib64/ld-linux-x86-64.so.2` and dependency `libc.so.6` for every file. LIEF reports 0 imported symbols; pyelftools reads the nine-byte entry as `31ffb83c0000000f05`.

| File | SHA-256 | LIEF type | pyelftools type |
| --- | --- | --- | --- |
| `home/v/.local/bin/cloud-watch` | `4d082fb6fcd4eb12...` | DYN | ET_DYN |
| `home/v/.local/bin/search-index` | `682a3478cdf36195...` | DYN | ET_DYN |
| `home/v/.local/bin/session-check` | `90f9cf45c1eda7f9...` | DYN | ET_DYN |
| `home/v/.local/bin/session-helper` | `9ffcbf70a42f5f49...` | DYN | ET_DYN |
| `home/v/.local/bin/thumbnail-helper` | `6315177e1798fa58...` | DYN | ET_DYN |

### XDG autostart: PyXDG and raw reader

Both readers agree on Type, Exec and Hidden. The raw reader also checks the exact synthetic marker.

| File | Exec | Hidden | Marker |
| --- | --- | --- | --- |
| `home/v/.config/autostart/artifactforge-1-session-helper.desktop` | `/home/v/.local/bin/session-helper` | false | `ARTIFACTFORGE` |
| `home/v/.config/autostart/artifactforge-2-thumbnail-helper.desktop` | `/home/v/.local/bin/thumbnail-helper` | false | `ARTIFACTFORGE` |
| `home/v/.config/autostart/artifactforge-3-cloud-watch.desktop` | `/home/v/.local/bin/cloud-watch` | false | `ARTIFACTFORGE` |

### Bash history: dissect.target and raw reader

Both readers agree on the records in `home/v/.bash_history`. They read history as data; neither executes a command.

| Order | UTC timestamp | Epoch | Command |
| --- | --- | --- | --- |
| 0 | 2024-05-17T14:47:19+00:00 | 1715957239 | `: 'ARTIFACTFORGE-SYNTHETIC-LINUX'` |
| 1 | 2024-05-17T14:48:19+00:00 | 1715957299 | `/home/v/.local/bin/session-helper` |
| 2 | 2024-05-17T14:49:19+00:00 | 1715957359 | `/home/v/.local/bin/session-check` |
| 3 | 2024-05-17T14:50:19+00:00 | 1715957419 | `/home/v/.local/bin/search-index` |

## Answer key

Byte-derived answers are in [`ARTIFACT_ANSWERS.json`](ARTIFACT_ANSWERS.json). Each answer joins at least two artifacts.
