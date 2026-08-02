# Windows: five historical hashes resolved against resident bytes

> **Synthetic.** Every byte here was generated. No hash, UUID, URL or path in this directory identifies anything real, and none should be submitted to a blocklist or a threat-intelligence platform. See [`../../SECURITY.md`](../../SECURITY.md).

Five binaries are resident. Five of eight Amcache rows carry `FileId` SHA-1 values that each resolve to exactly one of those binaries, while stale rows remain noise. The answer map records the resident SHA-256 values re-derived from the loose bytes. Run-key and prefetch evidence provide separate persistence/execution context without selecting the hash answers by filename or stored order.

Regenerate with `scripts/make-samples.sh`. The bytes are deterministic, so a regeneration that differs is a change in the generator, not in the weather.

## What the declared readers see

### pefile — every binary present

```
chrome.exe               sha256=79dc455016a4228b...  imphash=b32dcdf06d1ef56c876e6311443bcc0f
gimp.exe                 sha256=4db1b3314f43e49c...  imphash=de5f09aab665394f7c2928c8f97d17ac
python.exe               sha256=cfdb9af059e45ebb...  imphash=f3dd5c4d58621c89b44ef7ee32537f42
teams.exe                sha256=438814886dd0d643...  imphash=93089d862dbd00f661abb0e71157613d
wmi_perf.exe             sha256=c26429eefc92f7c2...  imphash=9ff5d0add3f7d84f765c276750473cbe
```

### regipy — Run key: three autostarts, one naming a program that is here

```
Dropbox                  C:\Users\jdupont\AppData\Local\Temp\wmi_perf.exe
Updater                  C:\Program Files\slack.exe
Steam                    C:\Program Files\audacity.exe
```

### regipy — Amcache: eight records, five whose hashes belong to resident files

```
audacity.exe             FileId=0000cee23c4ebc98eac0...  <-- matches wmi_perf.exe on disk
explorer.exe             FileId=00001fdd418f5d447df4...  <-- matches python.exe on disk
winscp.exe               FileId=0000a75f1466b3acaf08...
excel.exe                FileId=00005e6a0fb04ec7ab00...  <-- matches teams.exe on disk
steam.exe                FileId=00002cecfe6716cb353c...
mspaint.exe              FileId=00007de8b94495f87a80...  <-- matches chrome.exe on disk
firefox.exe              FileId=000072506a42b432ed3e...  <-- matches gimp.exe on disk
onedrive.exe             FileId=000071fd3daeab771f15...
```

### libscca (what plaso uses) — prefetch

```
GIMP.EXE                 run_count=5  hash=0x288c0f24
LICENSING.EXE            run_count=1  hash=0x14eab808  <-- not on disk
PYTHON.EXE               run_count=4  hash=0x17ed6d59
WMI_PERF.EXE             run_count=6  hash=0x1f98407a
```

## The answers

In [`ARTIFACT_ANSWERS.json`](ARTIFACT_ANSWERS.json). Each one requires reading at least two of the files above together.
