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
| `home/v/.local/bin/af-sync` | `2d70362529921fee...` | DYN | ET_DYN |
| `home/v/.local/bin/backup-watch` | `c0cae50146ca7d52...` | DYN | ET_DYN |
| `home/v/.local/bin/cache-helper` | `2b78817fa6b3241e...` | DYN | ET_DYN |
| `home/v/.local/bin/network-watch` | `9de5e447ced20b61...` | DYN | ET_DYN |
| `home/v/.local/bin/update-check` | `cd6f9cfc8da03941...` | DYN | ET_DYN |

### XDG autostart: PyXDG and raw reader

Both readers agree on Type, Exec and Hidden. The raw reader also checks the exact synthetic marker.

| File | Exec | Hidden | Marker |
| --- | --- | --- | --- |
| `home/v/.config/autostart/artifactforge-1-update-check.desktop` | `/home/v/.local/bin/update-check` | false | `ARTIFACTFORGE` |
| `home/v/.config/autostart/artifactforge-2-af-sync.desktop` | `/home/v/.local/bin/af-sync` | false | `ARTIFACTFORGE` |
| `home/v/.config/autostart/artifactforge-3-backup-watch.desktop` | `/home/v/.local/bin/backup-watch` | false | `ARTIFACTFORGE` |

### Bash history: dissect.target and raw reader

Both readers agree on the records in `home/v/.bash_history`. They read history as data; neither executes a command.

| Order | UTC timestamp | Epoch | Command |
| --- | --- | --- | --- |
| 0 | 2025-05-29T16:16:27+00:00 | 1748535387 | `: 'ARTIFACTFORGE-SYNTHETIC-LINUX'` |
| 1 | 2025-05-29T16:17:27+00:00 | 1748535447 | `/home/v/.local/bin/update-check` |
| 2 | 2025-05-29T16:18:27+00:00 | 1748535507 | `/home/v/.local/bin/cache-helper` |
| 3 | 2025-05-29T16:19:27+00:00 | 1748535567 | `/home/v/.local/bin/network-watch` |

## Answer key

Byte-derived answers are in [`ARTIFACT_ANSWERS.json`](ARTIFACT_ANSWERS.json). Each answer joins at least two artifacts.
