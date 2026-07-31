# Windows: a persisted binary, and a hash that points elsewhere

> **Synthetic.** Every byte here was generated. No hash, UUID, URL or path in this directory identifies anything real, and none should be submitted to a blocklist or a threat-intelligence platform. See [`../../SECURITY.md`](../../SECURITY.md).

Five binaries. One Run-key value names a program that is present; Amcache's recorded hashes match a *different* one, because the persisted binary is recorded under the hash of the version Amcache saw. One prefetch record names a program that is no longer on disk. Following names and following hashes lead to different files, which is what makes each of them a pivot rather than a lookup.

Regenerate with `scripts/make-samples.sh`. The bytes are deterministic, so a regeneration that differs is a change in the generator, not in the weather.

## What real tools see

### pefile — every binary present

```
acrord32.exe             sha256=f9192f15dcb361d9...  imphash=391916e482252b8db28e0680e04c743e
calc.exe                 sha256=4e9af850ee8557f3...  imphash=488a0ce187f360bcd9b9ce8cb04c7199
onedrive.exe             sha256=7b66ac8f29bc34cd...  imphash=c7972c33d207975641133256550e12f7
putty.exe                sha256=0b7be563d74a2a32...  imphash=634a14fcdb4364b396dcc1c67aa18197
winlogon_h.exe           sha256=3128f4b32bdddab9...  imphash=31e964de5fd56a9caf08a1435c233608
```

### regipy — Run key: three autostarts, one naming a program that is here

```
LicenseCheck             C:\Users\tsvensson\AppData\Local\Temp\winlogon_h.exe
WmiPerfMon               C:\Program Files\mspaint.exe
DllHostUp                C:\Program Files\slack.exe
```

### regipy — Amcache: eight records, one whose hash belongs to a resident file

```
onedrive.exe             FileId=0000fc41e187ecf0180d...  <-- matches onedrive.exe on disk
winlogon_h.exe           FileId=00002f3544b2bff1b248...  
spotify.exe              FileId=0000a1f1531c3a672334...  
python.exe               FileId=0000d1bda268b1ddf2c8...  
audacity.exe             FileId=0000e47ff8fbb41d06f4...  
chrome.exe               FileId=00009ccc11a27de384ad...  
explorer.exe             FileId=0000b2d634b13169c1cd...  
mspaint.exe              FileId=00005568530759d2e5c7...  
```

### libscca (what plaso uses) — prefetch

```
ONEDRIVE.EXE             run_count=2  hash=0xfbda2740
PRINTSVC.EXE             run_count=2  hash=0x2b5c9c4f  <-- not on disk
PUTTY.EXE                run_count=2  hash=0xf1c28886
WINLOGON_H.EXE           run_count=9  hash=0x5a5d06c6
```

## The answers

In [`ARTIFACT_ANSWERS.json`](ARTIFACT_ANSWERS.json). Each one requires reading at least two of the files above together.
