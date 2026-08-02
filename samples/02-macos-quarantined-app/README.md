# macOS: five quarantine UUIDs resolved to download events

> **Synthetic.** Every byte here was generated. No hash, UUID, URL or path in this directory identifies anything real, and none should be submitted to a blocklist or a threat-intelligence platform. See [`../../SECURITY.md`](../../SECURITY.md).

Five applications each have a real Mach-O binary and a strict serialized `com.apple.quarantine` xattr sidecar. Each xattr UUID resolves to exactly one `QuarantineEventsV2` URL; the answer map is re-derived from those emitted records. TCC, knowledgeC and LaunchAgent records remain independent incident context.

Regenerate with `scripts/make-samples.sh`. The bytes are deterministic, so a regeneration that differs is a change in the generator, not in the weather.

## What the declared readers see

### LIEF — every Mach-O present, with the symhash recomputed from its symbol table

```
com.claybourne.editor      ARM64    cmds=15  symhash=130e55ac5a3bd4df93f5048e8cdd4e76
com.harrowgate.mail        ARM64    cmds=14  symhash=a3c4c463a149bdf162de8e8cea121c74
com.windrow.updater        ARM64    cmds=16  symhash=1c8c9a86dc2a3ee83b53578d641a26a5
io.stonewell.daemon        ARM64    cmds=14  symhash=ff94752c32b98b7e8de7666a18551d52
net.glasswing.relay        ARM64    cmds=15  symhash=2f23ed14aff7f8ca7c69bd5575de5ccb
```

### sqlite3 — TCC: two clients allowed, two refused

```
net.glasswing.relay        kTCCServiceScreenCapture           auth_value=2
com.windrow.updater        kTCCServiceAppleEvents             auth_value=2
com.harrowgate.mail        kTCCServiceAppleEvents             auth_value=0
io.stonewell.daemon        kTCCServiceCamera                  auth_value=0
```

### sqlite3 — knowledgeC: which of them was actually used

```
net.glasswing.relay
com.harrowgate.mail
com.claybourne.editor
```

### sqlite3 — QuarantineEventsV2: five downloads, joined by the xattr UUID

```
9A407417-E48D-4E1A-9FF0-EF93A8E47579  Microsoft Edge   https://assets.rogue.invalid/downloads/fc25eac1aba4c9fb9d5ff6f0.dmg
B89A214D-F553-48DE-B244-D7769C733CD7  Microsoft Edge   https://assets.rogue.invalid/downloads/8b7aafd7510ad78f05718350.dmg
7055FE58-B20C-4D77-969B-71D0B3FA0DED  Microsoft Edge   https://assets.rogue.invalid/downloads/43cf2d42f7c7210ed4a5c039.dmg
B5A12A82-2E17-47BA-A5FC-BD49B42C7247  Microsoft Edge   https://assets.rogue.invalid/downloads/86a80f3e9de69e6a1bd4bc12.dmg
C4BB5A39-013C-4952-BDBC-63A595F6E567  Microsoft Edge   https://assets.rogue.invalid/downloads/5a1bd9693bf427cfcc846bf8.dmg
```

### plistlib — LaunchAgents

```
com.claybourne.editor      /Users/rkumar/Library/Application Support/com.claybourne.editor/editor
io.stonewell.daemon        /Users/rkumar/Library/Application Support/io.stonewell.daemon/daemon
net.glasswing.relay        /Users/rkumar/Library/Application Support/net.glasswing.relay/relay
```

## The answers

In [`ARTIFACT_ANSWERS.json`](ARTIFACT_ANSWERS.json). Each one requires reading at least two of the files above together.
