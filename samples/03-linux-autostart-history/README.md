# Linux: one resident named by XDG autostart and Bash history

> **Synthetic.** Every byte here was generated. No hash, UUID, URL or path in this directory identifies anything real, and none should be submitted to a blocklist or a threat-intelligence platform. See [`../../SECURITY.md`](../../SECURITY.md).

Five nested ELF files are resident. Three XDG autostart records name one set of three paths; a timestamped Bash history names another set of three. Their unique shared path identifies the subject, and that exact guest path maps to one recursive served path whose SHA-256 is computed from the committed ELF bytes.

This is naming evidence, not an activation claim: parser acceptance does not prove that a desktop session launched an entry, and shell history is not proof that a command ran. Fixture Core v1 does not bind executable modes, so the released files are normalized to 0644 and are not an activation-ready filesystem. The ELF declares the glibc loader and `libc.so.6`, while the main object imports and calls no libc function; external loader/dependency code is out of scope and on a real execution attempt the dynamic loader would run before its nine-byte direct-exit entry. The files are deliberately minimal, not compiler-shaped. Do not execute them, run `ldd`, launch the desktop entries, or source/evaluate the history.

Regenerate with `scripts/make-samples.sh`. The bytes are deterministic, so a regeneration that differs is a change in the generator, not in the weather.

## What the declared readers see

### LIEF — five ELF64 PIE files declare glibc but import no functions

```
home/v/.local/bin/font-index  type=DYN machine=X86_64 interp=/lib64/ld-linux-x86-64.so.2 needed=libc.so.6 imports=0 sha256=fe7a74d61e0e9eaf...
home/v/.local/bin/print-helper  type=DYN machine=X86_64 interp=/lib64/ld-linux-x86-64.so.2 needed=libc.so.6 imports=0 sha256=174a38bb8c6f3f73...
home/v/.local/bin/profile-agent  type=DYN machine=X86_64 interp=/lib64/ld-linux-x86-64.so.2 needed=libc.so.6 imports=0 sha256=62c4d3d12540548f...
home/v/.local/bin/session-check  type=DYN machine=X86_64 interp=/lib64/ld-linux-x86-64.so.2 needed=libc.so.6 imports=0 sha256=64dec881b31c2130...
home/v/.local/bin/theme-agent  type=DYN machine=X86_64 interp=/lib64/ld-linux-x86-64.so.2 needed=libc.so.6 imports=0 sha256=ac05d4be788cca1d...
```

### pyelftools — independently reads the same loader, dependency and nine-byte entry

```
home/v/.local/bin/font-index  type=ET_DYN machine=EM_X86_64 interp=/lib64/ld-linux-x86-64.so.2 needed=libc.so.6 .text=31ffb83c0000000f05
home/v/.local/bin/print-helper  type=ET_DYN machine=EM_X86_64 interp=/lib64/ld-linux-x86-64.so.2 needed=libc.so.6 .text=31ffb83c0000000f05
home/v/.local/bin/profile-agent  type=ET_DYN machine=EM_X86_64 interp=/lib64/ld-linux-x86-64.so.2 needed=libc.so.6 .text=31ffb83c0000000f05
home/v/.local/bin/session-check  type=ET_DYN machine=EM_X86_64 interp=/lib64/ld-linux-x86-64.so.2 needed=libc.so.6 .text=31ffb83c0000000f05
home/v/.local/bin/theme-agent  type=ET_DYN machine=EM_X86_64 interp=/lib64/ld-linux-x86-64.so.2 needed=libc.so.6 .text=31ffb83c0000000f05
```

### PyXDG — three XDG desktop-entry records

```
home/v/.config/autostart/artifactforge-1-session-check.desktop  Type=Application Exec=/home/v/.local/bin/session-check Hidden=false
home/v/.config/autostart/artifactforge-2-theme-agent.desktop  Type=Application Exec=/home/v/.local/bin/theme-agent Hidden=false
home/v/.config/autostart/artifactforge-3-profile-agent.desktop  Type=Application Exec=/home/v/.local/bin/profile-agent Hidden=false
```

### bounded raw reader — the same XDG values and exact marker

```
home/v/.config/autostart/artifactforge-1-session-check.desktop  Type=Application Exec=/home/v/.local/bin/session-check Hidden=false marker=ARTIFACTFORGE
home/v/.config/autostart/artifactforge-2-theme-agent.desktop  Type=Application Exec=/home/v/.local/bin/theme-agent Hidden=false marker=ARTIFACTFORGE
home/v/.config/autostart/artifactforge-3-profile-agent.desktop  Type=Application Exec=/home/v/.local/bin/profile-agent Hidden=false marker=ARTIFACTFORGE
```

### dissect.target — timestamped Bash-history records read as data

```
home/v/.bash_history  2024-01-15T05:00:00+00:00 order=0 command=: 'ARTIFACTFORGE-SYNTHETIC-LINUX'
home/v/.bash_history  2024-01-15T05:00:01+00:00 order=1 command=/home/v/.local/bin/session-check
home/v/.bash_history  2024-01-15T05:00:02+00:00 order=2 command=/home/v/.local/bin/print-helper
home/v/.bash_history  2024-01-15T05:00:03+00:00 order=3 command=/home/v/.local/bin/font-index
```

### bounded raw reader — the same Bash epochs and command strings

```
home/v/.bash_history  epoch=1705294800 command=: 'ARTIFACTFORGE-SYNTHETIC-LINUX'
home/v/.bash_history  epoch=1705294801 command=/home/v/.local/bin/session-check
home/v/.bash_history  epoch=1705294802 command=/home/v/.local/bin/print-helper
home/v/.bash_history  epoch=1705294803 command=/home/v/.local/bin/font-index
```

## The answers

In [`ARTIFACT_ANSWERS.json`](ARTIFACT_ANSWERS.json). Each one requires reading at least two of the files above together.
