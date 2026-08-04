# macOS: five quarantine UUIDs resolved to download events

> **Synthetic sample.** Nothing here was collected from a real host or incident. Do not submit these values to a blocklist or threat-intelligence platform. See [`../../SECURITY.md`](../../SECURITY.md).

## Scenario

Five applications each have a real Mach-O binary and a strict serialized `com.apple.quarantine` xattr sidecar. Each xattr UUID resolves to exactly one `QuarantineEventsV2` URL; the answer map is re-derived from those emitted records. TCC, knowledgeC and LaunchAgent records provide separate modeled context.

## Scope

The records model grants, in-focus observations, downloads and persistence configuration. They are synthetic records, not proof that a real application was allowed, used, downloaded or launched.

## Reproduce

From the repository root, run `scripts/make-samples.sh`. A byte difference means the generator or its declared inputs changed.

## Reader results

### Mach-O files: LIEF

The symhash is recomputed from each binary's undefined symbols.

| File | CPU | Load commands | Symhash |
| --- | --- | --- | --- |
| `com.claybourne.editor` | ARM64 | 15 | `130e55ac5a3bd4df93f5048e8cdd4e76` |
| `com.harrowgate.mail` | ARM64 | 14 | `a3c4c463a149bdf162de8e8cea121c74` |
| `com.windrow.updater` | ARM64 | 16 | `1c8c9a86dc2a3ee83b53578d641a26a5` |
| `io.stonewell.daemon` | ARM64 | 14 | `ff94752c32b98b7e8de7666a18551d52` |
| `net.glasswing.relay` | ARM64 | 15 | `2f23ed14aff7f8ca7c69bd5575de5ccb` |

### TCC records: sqlite3

| Client | Service | Auth value |
| --- | --- | --- |
| `net.glasswing.relay` | `kTCCServiceScreenCapture` | 2 |
| `com.windrow.updater` | `kTCCServiceAppleEvents` | 2 |
| `com.harrowgate.mail` | `kTCCServiceAppleEvents` | 0 |
| `io.stonewell.daemon` | `kTCCServiceCamera` | 0 |

### Modeled in-focus records: sqlite3

| knowledgeC client |
| --- |
| `net.glasswing.relay` |
| `com.harrowgate.mail` |
| `com.claybourne.editor` |

### QuarantineEventsV2: sqlite3

Each UUID is joined to the corresponding serialized quarantine-xattr sidecar.

| UUID | Agent | Download URL |
| --- | --- | --- |
| `9A407417-E48D-4E1A-9FF0-EF93A8E47579` | Microsoft Edge | `https://assets.rogue.invalid/downloads/fc25eac1aba4c9fb9d5ff6f0.dmg` |
| `B89A214D-F553-48DE-B244-D7769C733CD7` | Microsoft Edge | `https://assets.rogue.invalid/downloads/8b7aafd7510ad78f05718350.dmg` |
| `7055FE58-B20C-4D77-969B-71D0B3FA0DED` | Microsoft Edge | `https://assets.rogue.invalid/downloads/43cf2d42f7c7210ed4a5c039.dmg` |
| `B5A12A82-2E17-47BA-A5FC-BD49B42C7247` | Microsoft Edge | `https://assets.rogue.invalid/downloads/86a80f3e9de69e6a1bd4bc12.dmg` |
| `C4BB5A39-013C-4952-BDBC-63A595F6E567` | Microsoft Edge | `https://assets.rogue.invalid/downloads/5a1bd9693bf427cfcc846bf8.dmg` |

### LaunchAgents: plistlib

| Label | Program |
| --- | --- |
| `com.claybourne.editor` | `/Users/rkumar/Library/Application Support/com.claybourne.editor/editor` |
| `io.stonewell.daemon` | `/Users/rkumar/Library/Application Support/io.stonewell.daemon/daemon` |
| `net.glasswing.relay` | `/Users/rkumar/Library/Application Support/net.glasswing.relay/relay` |

## Answer key

Byte-derived answers are in [`ARTIFACT_ANSWERS.json`](ARTIFACT_ANSWERS.json). Each answer joins at least two artifacts.
