# Windows: five historical hashes resolved against resident bytes

> **Synthetic sample.** Nothing here was collected from a real host or incident. Do not submit these values to a blocklist or threat-intelligence platform. See [`../../SECURITY.md`](../../SECURITY.md).

## Scenario

Five resident PEs are joined to five of eight Amcache FileId SHA-1 values. The answer map records SHA-256 values recomputed from those PE bytes.

| Surface | Byte-derived relation | Role |
| --- | --- | --- |
| Run key | path to resident PE and Prefetch record | persistence context |
| Chromium History | reserved-URL SHA-256 to persisted PE | download context |
| Task XML | path, size and SHA-256 to another PE | configuration reference |
| Shell Link | path, size and SHA-256 to another PE | file reference |
| Prefetch | executable path and run count | execution context |

## Scope

The Task is disabled and trigger-free. The Shell Link has no arguments, network target or activation evidence. Their parser agreement and byte joins do not prove Task registration, shortcut activation or target execution.

## Reproduce

From the repository root, run `scripts/make-samples.sh`. A byte difference means the generator or its declared inputs changed.

## Reader results

### PE files: pefile

| File | SHA-256 | IMPHASH |
| --- | --- | --- |
| `chrome.exe` | `79dc455016a4228b...` | `b32dcdf06d1ef56c876e6311443bcc0f` |
| `gimp.exe` | `4db1b3314f43e49c...` | `de5f09aab665394f7c2928c8f97d17ac` |
| `python.exe` | `cfdb9af059e45ebb...` | `f3dd5c4d58621c89b44ef7ee32537f42` |
| `teams.exe` | `438814886dd0d643...` | `93089d862dbd00f661abb0e71157613d` |
| `wmi_perf.exe` | `c26429eefc92f7c2...` | `9ff5d0add3f7d84f765c276750473cbe` |

### Run key: regipy

| Value | Command | Resident PE |
| --- | --- | --- |
| `Dropbox` | `C:\Users\jdupont\AppData\Local\Temp\wmi_perf.exe` | `wmi_perf.exe` |
| `Updater` | `C:\Program Files\slack.exe` | none |
| `Steam` | `C:\Program Files\audacity.exe` | none |

### Amcache: regipy

Five of eight FileId SHA-1 values join to resident bytes.

| Recorded name | FileId | Resident match |
| --- | --- | --- |
| `audacity.exe` | `0000cee23c4ebc98eac0...` | `wmi_perf.exe` |
| `explorer.exe` | `00001fdd418f5d447df4...` | `python.exe` |
| `winscp.exe` | `0000a75f1466b3acaf08...` | none |
| `excel.exe` | `00005e6a0fb04ec7ab00...` | `teams.exe` |
| `steam.exe` | `00002cecfe6716cb353c...` | none |
| `mspaint.exe` | `00007de8b94495f87a80...` | `chrome.exe` |
| `firefox.exe` | `000072506a42b432ed3e...` | `gimp.exe` |
| `onedrive.exe` | `000071fd3daeab771f15...` | none |

### Compressed Prefetch v30: raw MAM reader, pyscca and Dissect

All four records pass expected-size MAM framing, the closed v30 profile, pyscca acceptance and typed pyscca/Dissect semantic consensus. Their shared volume token is `\VOLUME{01db3526b63c5c00-e9593c63}`; each marker is bound to that token.

| Executable | Version | Run count | Vista hash | On disk |
| --- | --- | --- | --- | --- |
| `GIMP.EXE` | 30 | 5 | `0x949a752e` | yes |
| `LICENSING.EXE` | 30 | 1 | `0x898190bc` | no |
| `PYTHON.EXE` | 30 | 4 | `0xa9647ccf` | yes |
| `WMI_PERF.EXE` | 30 | 6 | `0x35012f05` | yes |

### Chromium completed downloads: sqlite3

| Target | Bytes | Database hash | URL SHA-256 | Resident match |
| --- | --- | --- | --- | --- |
| `C:\Users\jdupont\Downloads\filezilla.exe` | 2729 | empty BLOB | `07ec572b835a36f7...` | none |
| `C:\Users\jdupont\AppData\Local\Temp\wmi_perf.exe` | 2729 | empty BLOB | `c26429eefc92f7c2...` | `wmi_perf.exe` |
| `C:\Users\jdupont\Downloads\node.exe` | 2729 | empty BLOB | `231064a0f08dfb5e...` | none |

### Task XML: ElementTree, wire reader and Dissect

ElementTree and the bounded wire reader agree on the closed Task profile. Dissect is a separate consumer observation.

| Field | Observed value |
| --- | --- |
| Artifact | `ArtifactForgeMaintenance.task.xml` |
| Task | `Maintenance-5ca3fcea623b` |
| Command | `C:\Program Files\gimp.exe` |
| Profile | enabled=false; demand_start=false; triggers=0; actions=1 |
| Wire | encoding=UTF-16LE+BOM; lines=17; marker_count=2 |
| Dissect-only surfaces | principals=0; arguments=None; working_directory=None; action_context=None |
| Resident join | `gimp.exe`; size=2729; sha256=`4db1b3314f43e49c...`; path source=Prefetch |

### Shell Link: liblnk, LnkParse3 and raw reader

liblnk and LnkParse3 agree on their typed semantic intersection. The bounded raw reader owns the exact wire profile.

| Field | Observed value |
| --- | --- |
| Artifact | `ArtifactForgeMaintenance.lnk` |
| Target | `C:\Program Files\python.exe` |
| External consensus | target=C:\Program Files\python.exe,size=2729,volume=SYSTEM/e9593c63,flags=0x86,blocks=0 |
| Raw description | System Maintenance [ARTIFACTFORGE SYNTHETIC] |
| Profile | profile=local-file-v1,target=C:\Program Files\python.exe,size=2729,volume=SYSTEM/e9593c63,flags=0x86,blocks=0,description=marked |
| Resident join | `python.exe`; size=2729; sha256=`cfdb9af059e45ebb...`; path source=Prefetch |
| Relation | distinct Task/Link targets; neither is a persistence/browser target |

## Answer key

Byte-derived answers are in [`ARTIFACT_ANSWERS.json`](ARTIFACT_ANSWERS.json). Each answer joins at least two artifacts.
