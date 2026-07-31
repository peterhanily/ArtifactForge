# macOS: a quarantined app that was granted access, and used

> **Synthetic.** Every byte here was generated. No hash, UUID, URL or path in this directory identifies anything real, and none should be submitted to a blocklist or a threat-intelligence platform. See [`../../SECURITY.md`](../../SECURITY.md).

Five applications, each with a real Mach-O binary and a quarantine record. Two hold an allowed TCC grant; only one of those also appears in knowledgeC as having been used. Everything after that hangs off the quarantine UUID in that app's `com.apple.quarantine` xattr, which is the join macOS actually gives a responder.

Regenerate with `scripts/make-samples.sh`. The bytes are deterministic, so a regeneration that differs is a change in the generator, not in the weather.

## What real tools see

### LIEF — every Mach-O present, with the symhash recomputed from its symbol table

```
com.apple.Notes            ARM64    cmds=14  symhash=6b319ab74a8587a2118b2da29130c48f
com.microsoft.VSCode       ARM64    cmds=15  symhash=85e0cb02688d7d3c9e402259c2f28687
com.riverstone.helper      ARM64    cmds=14  symhash=d4b83854692eecb5ee82c590119e4b4c
io.slatebeck.agent         ARM64    cmds=16  symhash=74e8ea890b710c38e2c05da8fb3b0e20
org.pelagic.tool           ARM64    cmds=15  symhash=75e96658570d9db2e4984f2d852fd825
```

### sqlite3 — TCC: two clients allowed, two refused

```
org.pelagic.tool           kTCCServiceCamera                  auth_value=2
com.riverstone.helper      kTCCServiceAppleEvents             auth_value=2
com.apple.Notes            kTCCServiceAppleEvents             auth_value=0
io.slatebeck.agent         kTCCServiceCamera                  auth_value=0
```

### sqlite3 — knowledgeC: which of them was actually used

```
org.pelagic.tool
com.apple.Notes
com.microsoft.VSCode
```

### sqlite3 — QuarantineEventsV2: five downloads, joined by the xattr UUID

```
B1281D32-7B03-419E-92F0-26A97BA22B5D  Brave Browser    https://pkg.untrusted.test/org.pelagic.tool.dmg
E555543F-8659-423F-983D-82B9FC5F0158  Safari           https://static.threat.example/com.riverstone.helper.dmg
D8AA6C04-D0C9-4057-ADF5-F4E5430DA278  Safari           https://static.threat.example/io.slatebeck.agent.dmg
008A4D56-4111-4A7F-94DD-E43E4AFB538E  Safari           https://dl.malicious.test/com.apple.Notes.dmg
E1697044-C3EB-4701-85EA-A45F647E0DA9  curl             https://static.threat.example/com.microsoft.VSCode.dmg
```

### plistlib — LaunchAgents

```
com.microsoft.VSCode       /Users/ekallio/Library/Application Support/com.microsoft.VSCode/VSCode
io.slatebeck.agent         /Users/ekallio/Library/Application Support/io.slatebeck.agent/agent
org.pelagic.tool           /Users/ekallio/Library/Application Support/org.pelagic.tool/tool
```

## The answers

In [`ARTIFACT_ANSWERS.json`](ARTIFACT_ANSWERS.json). Each one requires reading at least two of the files above together.
