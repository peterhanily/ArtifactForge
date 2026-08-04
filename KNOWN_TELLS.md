# Known tells

ArtifactForge emits deterministic synthetic data. This file records the fidelity limit and
in-band marker for every supported format.

`tests/test_known_tells.py` enforces the inventory in both directions. A format cannot ship
without a section, and a section cannot remain after its format is removed. This document is
the format-limit source of truth. `fidelity-scorecard.json` records the narrower measured gate
failures and declared assurance gaps.

Generated binaries are payload-free by construction, under the precise executable-code checks
and limitations documented in
[`docs/inert-by-construction.md`](docs/inert-by-construction.md).

## pe

- **Payload-free.** The `.text` section starts with one `0xC3` (`ret`) and the rest is zero
  padding. The fixed DOS stub separately prints its standard sentence and exits.
- **Minimal, not compiler-realistic.** Two sections (`.text`, `.rdata`), no resources, no rich
  header, no relocations, no TLS. The internals do not resemble any real compiler's output,
  and pefile will note that a large fraction of the file is zero bytes.
- **IMPHASH is byte-derived.** The seed-deterministic import table names common DLLs
  (kernel32, advapi32, user32, ws2_32). pefile and LIEF independently enumerate the DLL and
  function sequence, each confirms pefile/VT-normalised IMPHASH semantics, and Gate 1 requires
  their results to agree. The selection is synthetic and does not come from a real program.
- **`TimeDateStamp` is pinned to 0** so the bytes never depend on a clock.
- **The MS-DOS header and stub are the standard MSVC ones**, byte for byte, including the
  "This program cannot be run in DOS mode." message. A PE without them is easily
  distinguishable from a real one. The community rule `HasModified_DOS_Message` fires on
  every binary that omits the message. The stub is 16-bit code that prints a sentence and
  exits, and Gate 3 requires it byte-exact, because it is the one region of a PE where
  arbitrary code is conventional and nothing reads it.
- **Marked.** The overlay carries `ARTIFACTFORGE-SYNTHETIC-<16 hex>`.

## macho

- **Statically bounded entry body.** `__text` is `mov w0, #0 ; ret` and nothing else. It is the
  arm64 analogue of the PE's single `ret`. Gate 3 binds `LC_MAIN` to those exact bytes and
  rejects alternate emitted entry surfaces. ArtifactForge does not execute the Mach-O, so
  parser/signature acceptance and instruction inspection do not prove that a particular
  macOS loader reaches the entry or that a process returns zero.
- **symhash and cdhash are structure-derived.** Undefined external symbols in `LC_SYMTAB`
  yield the same symhash that threatstream/symhash and yara-x compute. The ad-hoc
  `CS_SuperBlob` yields the cdhash reported by `codesign -d`.
- **Thin arm64, not fat.** A single-architecture `MH_EXECUTE`, where a shipped macOS binary is
  often universal.
- **Older linker idiom.** Uses `LC_DYLD_INFO_ONLY` bind opcodes. A 2024-era clang emits
  `LC_DYLD_CHAINED_FIXUPS`, `LC_FUNCTION_STARTS`, `LC_DATA_IN_CODE` and an exports trie. None
  of those are present, so `dyld_info -fixup_chains` will show nothing.
- **Ad-hoc signature only.** No Developer ID, no notarisation, no Info.plist slot. Apple's
  documented `spctl` assessment shape is a top-level app bundle, so neither a loose platform
  binary nor this loose generated Mach-O is a valid control/target pair. Earlier manual output
  is inconclusive, not evidence of Gatekeeper rejection. A future observation requires bound
  `.app` target/control bundles and remains scoped to their host and macOS policy state.
- **Marked.** `__TEXT,__cstring` carries `ARTIFACTFORGE-SYNTHETIC-<16 hex>`.

## hive

- **Minimal regf.** One hive bin, a single shared empty security descriptor for every key,
  `lf` subkey lists only, no classes, no big-data records. regipy and libregf accept this subset,
  which is sparser than a real hive.
- **Bounded registry names.** ASCII names use REGF's compressed form; non-ASCII names use
  UTF-16LE with the compression flag clear. Both declared readers must round-trip the same
  Unicode text. NULs, surrogates and names beyond the writer's 255-code-unit limit are rejected.
- **Consumer recognition is separately tested.** The base-block filenames are `Amcache.hve`
  and `\\System32\\config\\SOFTWARE`, allowing regipy's Amcache and Software-persistence
  plugins to recognise and extract the modeled records. Gate 1 separately requires regipy and
  libregf to agree on the complete typed modeled tree before its Amcache/SOFTWARE profile
  passes. This does not imply support for other plugins or the unmodeled structures of a full
  system hive.
- **Sparse chronology.** Legacy scene generation uses fixed hive timestamps. Fixture ABI v2
  supplies exact causal FILETIMEs per hive/key role, but still models only the small declared
  sequence rather than the write history of a real registry hive.
- **Marked.** A dedicated root `artifactforge_synthetic` key carries marker and notice values;
  the base-block filename remains the format-appropriate consumer identity.

## prefetch

- **Bounded v30 variant, not a complete Windows Prefetch history.** Current scenes emit one
  deterministic MAM algorithm-4 XPRESS-Huffman chunk containing Windows-10 v30 variant 1. The
  profile deliberately has exactly one metric, two filename strings and one volume, with no
  directory strings or MFT file references. A real record normally carries a much richer set
  of touched paths and references; version 31, alternate v30 layouts and multi-chunk streams
  remain outside the claim.
- **The Vista path hash and volume identity follow the emitted model.** The hash is computed
  from the uppercase UTF-16LE canonical device path. The recorded executable, disclosure
  marker and sole volume share `\VOLUME{<creation-FILETIME>-<serial>}`, while the executable
  tail remains uppercase. Writer and strict profile both enforce the same 260-character ASCII
  device-path ceiling and reject invalid Windows characters, trailing dot/space components and
  reserved DOS basenames. The serial and timestamps are synthetic inputs, not observations of
  a real NTFS volume.
- **Exact framing has one first-party owner.** A bounded expected-size reader validates MAM's
  declared output, the complete canonical Huffman table and the closed v30 byte layout.
  `pyscca` must accept the file, and `pyscca` plus Dissect must agree type-for-type on the
  exposed semantics. Dissect's decoder is EOF-driven and can expose fewer or more bytes than
  MAM declares, so it is a semantic consumer only, not an exact container or framing oracle.
- **The emitted set is closed, not best-effort.** Gate 2 independently counts captured `.pf`
  files, decodes each executable name from its bytes and requires the exact scene-declared
  count and name set. Deleting or substituting a non-pivot execution record is therefore red,
  even when the persisted and orphan pivots still exist.
- **Native decompression is still conditional.** A parse-only Windows canary uses
  `RtlGetCompressionWorkSpaceSize`/`RtlDecompressBufferEx` and compares the declared output
  with the expected-size reader, but no hosted Windows result exists yet. Even a successful
  hosted run would not show that Windows consumed or rejected bits after the declared output
  size.
- **The v17 API is compatibility-only.** Public `build_prefetch` and `prefetch_name_hash`
  retain byte-stable SCCA v17/XP behavior for callers and historical fixtures; current scenes
  call `build_prefetch_v30` explicitly. The still-unreleased `windows-loose-v2` identifier was
  compatibility-reset in place rather than renamed, so older generated v2 bytes remain bound
  to their source revision.
- **Deterministic run time and volume serial.** The volume serial remains synthetic. The v17
  compatibility API retains its fixed defaults; current Fixture ABI v2 derives v30 run and
  volume-creation FILETIMEs from its public causal clock.
- **Marked.** A reserved entry in the filename strings array.

## prefetch-v17

- **Compatibility output, not the current scene profile.** The public `build_prefetch` API
  intentionally preserves the uncompressed SCCA v17 layout for byte-stable callers and
  historical fixtures. Current generated scenes do not use it; they call
  `build_prefetch_v30` explicitly.
- **Sparse XP-era shape.** It carries one metric and one volume, with no directory strings or
  MFT references, and uses the XP/Server 2003 path hash. `windowsprefetch` and `pyscca` accept
  the bounded compatibility bytes, but that does not make them representative of a complete
  XP host history or a Windows-10 Prefetch record.
- **Marked.** A reserved UTF-16 filename-strings entry carries `ARTIFACTFORGE`.

## task-xml

- **Disabled configuration, not execution evidence.** The emitted Task Scheduler definition
  has no `Triggers` or `Principals`, sets both `Enabled` and `AllowStartOnDemand` to exact
  lowercase `false`, and contains exactly one argument-free `Exec/Command` naming an
  allowlisted resident PE. `Hidden` is also false. ArtifactForge does not register the task,
  enumerate or reopen it as a registered task, or run its command. Its presence proves only
  that a disabled serialized definition refers to that file.
- **Small canonical subset.** Only Task Scheduler schema versions 1.2 and 1.3 are emitted, as
  UTF-16LE with a BOM, CRLF framing and the exact Microsoft task namespace. The 16 KiB profile
  omits the broad scheduling, credentials, security-context, conditions, settings and action
  surfaces of real task definitions. The native Task Store guest path is modeled, but the
  portable carrier is not a registered Windows Task Scheduler store.
- **Consensus and consumer claims stay separate.** A standard-library ElementTree reader and
  a separately implemented canonical byte reader must agree type-for-type before the closed
  profile passes. dissect.target's ScheduledTasks loader is a third, responder-facing consumer
  observation; it is not folded into the two-reader consensus or treated as proof that Windows
  registered or scheduled the task.
- **Native canary is parse-only; hosted evidence is partial.** The Windows observer sets
  only an unregistered in-memory `TaskDefinition.XmlText` created with
  `TaskService.Connect`/`NewTask(0)`. It never calls a registration method. A hosted schema-v6
  run on the preceding revision accepted the task before a later Shell Link contract failure.
  A complete passing schema-v7 report for current source remains pending.
- **Marked.** The UTF-16 description and owned URI contain `ARTIFACTFORGE`; the description
  states that the task is synthetic, inert, disabled and trigger-free.

## shell-link

- **A local reference, not activation evidence.** The exact profile is a 76-byte
  `ShellLinkHeader`, one local `LinkInfo` with a 0x24-byte header and fixed-drive `VolumeID`,
  one Unicode display-name string and the terminal block. It carries no target ID list,
  network path, arguments, working directory, relative path, icon, hotkey, environment,
  Darwin data, tracker, property store, shim or other ExtraData. ArtifactForge neither resolves
  nor follows the target, so the `.lnk` proves only that its bytes refer to a resident PE.
- **Redundant path and bounded metadata, not Explorer fidelity.** The target path appears in
  both ANSI and UTF-16 `LinkInfo` fields and must agree exactly. The profile fixes archive-file
  attributes, normal show state, a bounded volume label/serial, target size and three
  whole-microsecond FILETIMEs. Zero means unset; nonzero values are deliberately limited to
  the portable 1970-through-2242 interval that the pinned LnkParse3 datetime surface preserves
  exactly. It is deliberately hand-assembled and lacks the target-ID and tracking data commonly
  found in links produced by Explorer.
- **External consensus has an explicit byte-layout owner.** The pinned liblnk and LnkParse3
  adapters must agree type-for-type on the semantic fields both expose. The strict first-party
  reader separately owns offset/extent checks, both empty common-path suffixes, the exact
  terminal block and the absence of trailing data; neither external library exposes all of
  those facts.
- **Pinned parser defect is excluded, not encoded around.** LnkParse3 1.6.0's Unicode
  common-suffix accessor advances four bytes beyond this profile's empty suffix and reads the
  following NameString. ArtifactForge does not distort the emitted bytes to satisfy that
  accessor; it excludes that field from consensus and leaves suffix extents to the strict
  first-party reader. The two reliable external views still agree on the full typed
  intersection.
- **Native canary is read-only; hosted evidence is partial.** The Windows observer opens
  the private-copy path only with `WScript.Shell.CreateShortcut`; it never calls `Save`,
  `Resolve` or `Run`. A hosted schema-v6 run on the preceding revision reached this call, but
  WSH returned an empty target path for the link with no `LinkTargetIDList`. The schema-v7
  contract records that state explicitly; a complete passing report remains pending.
- **Marked.** The Unicode display name ends with `[ARTIFACTFORGE SYNTHETIC]`.

## zone-identifier

- **Logical ADS bytes, not an NTFS observation.** Fixture ABI v2 binds `Zone.Identifier` as a
  named stream value in the manifest and never creates a native ADS on the development
  carrier. Passing assurance proves the declared bytes, not that Attachment Manager wrote or
  consumed them. The current Windows fixture gives this stream to exactly one downloaded
  resident PE, not to every resident PE. Incidental host ADS and xattrs remain outside
  raw-carrier verification.
- **Exact reduced profile.** The value is bounded to 2 KiB and contains four CRLF-terminated
  lines: `[ZoneTransfer]`, then `ZoneId`, `ReferrerUrl` and `HostUrl` in that order. The zone is
  exactly Internet zone 3; both fields are bounded, credential-free HTTPS URLs on reserved
  names and carry `ARTIFACTFORGE`. In current fixture output `ReferrerUrl` is the marked browser
  referrer and `HostUrl` is the distinct content-addressed final download URL. This is not a
  general INI or Zone.Identifier reader.
- **Two independent implementations.** Gate 1 gives the same immutable bytes to a
  standard-library `ConfigParser` adapter and a separately implemented raw line/key reader,
  requires type-exact agreement, and then applies the closed profile. Either parser refusing,
  returning the wrong shape or disagreeing keeps assurance red.
- **Marked.** Both logical URL fields carry the `ARTIFACTFORGE` anchor. The manifest and
  canonical release retain these stream bytes as data; they do not apply them to the host.

## sqlite

Covers Chromium `History`, knowledgeC, TCC and QuarantineEventsV2.

- **Versioned reduced schemas, not a general macOS schema claim or native application
  databases.** Only the tables and columns in each declared consumer-query profile are present.
  Passing those named queries says nothing about another plugin, query revision, browser
  migration or operating-system release; genuine application databases have many more
  columns, supporting tables, indices and triggers.
- **Chromium download surface is intentionally incomplete.** `History` contains only the
  bounded `downloads`, `downloads_url_chains` and marker tables needed by the declared
  completed-download query. It is not a full, native or Chromium-migratable History database.
  Chromium leaves the completed-download `hash` BLOB empty, so ArtifactForge keeps it empty
  and places its modeled digest in an explicitly synthetic content-addressed reserved final
  URL. Gate 1 proves the lowercase SHA-256 component is syntactically well formed; it has no PE
  bytes in that single-artifact check. Gate 2 re-hashes the one resident target, while Fixture
  Core additionally binds that target's logical `Zone.Identifier` host/referrer URLs, guest
  path and byte counts. Two other completed rows intentionally name absent files.
- **Owned leaf-only writer.** Current bytes use `artifactforge-owned-sqlite-leaf-v1`, a
  filesystem-free deterministic encoder rather than the host SQLite library. Header offset 96
  is zero because no SQLite library wrote the file; that sentinel is not producer provenance.
  The profile is bound by Fixture ABI v2. Historical v1 gallery bytes did embed a runtime
  SQLite release, and Fixture ABI v1 does not bind it in the fixture generator identity. Those
  cross-runtime-varying 0.5.0 vectors remain parse-only rather than being silently relabeled.
- **Deliberately narrow second reader.** Gate 1 pairs `sqlite3` with a first-party byte reader
  covering only 4096-byte rollback-mode databases whose schema objects own leaf table/index
  roots. It rejects WAL, freelists, pointer maps, interior pages, overflow and schema SQL
  outside the emitted grammar. Runtime-written and ArtifactForge-owned bytes are separate
  closed wire profiles; every current SQLite output must use the owned one. The pair must agree
  type-for-type before exact Chromium History, knowledgeC, TCC or QuarantineEventsV2 semantics
  are credited. This is independent implementation, not external validation or general SQLite
  support.
- **Reduced deterministic identities and chronology.** Rowids remain compact and synthetic.
  Fixture v2 derives unique knowledgeC UUIDv4 values from its content domain and binds each
  metadata hash to UUID plus bundle; its timestamps come from a small causal clock, not a real
  usage history. The legacy rowid-shaped UUID profile remains parseable but cannot mix with v2.
- **Marked.** A reserved `artifactforge_synthetic` table.

## plist

- **LaunchAgent only**, with a minimal key set and a pinned `StartInterval`.
- **Deliberately narrow second reader.** Gate 1 pairs `plistlib` with a bounded first-party
  `bplist00` decoder and requires a type-exact object-graph match before checking the exact
  six-key LaunchAgent profile. Unsupported tokens, noncanonical widths, cycles, aliases of
  containers and resource-limit violations are red; this is not general property-list support
  or external validation.
- **Marked.** A reserved `artifactforge_synthetic` key. launchd ignores keys it does not know.

## elf

- **A bounded direct-exit entry, not a claim that no code runs.** The sole executable segment
  is exactly `xor edi,edi; mov eax,60; syscall`, a nine-byte x86-64 `exit(0)` body. The ELF also
  declares `/lib64/ld-linux-x86-64.so.2`, so a real execution attempt enters the dynamic
  loader before that entry. ArtifactForge never executes the file and never invokes `ldd`.
- **The main object declares glibc but imports no callable symbol.** `libc.so.6` is the sole
  `DT_NEEDED` value, while the main object has no dynamic symbol table, imported functions,
  relocations, PLT/GOT, constructors, finalizers, TLS or alternate entry surface. External
  loader/dependency code is outside that claim and the loader runs first. It should not be
  described as a realistic glibc program merely because its dynamic metadata names libc.
- **Minimal, not compiler-shaped.** Hand-assembled ELF64 little-endian x86-64 `ET_DYN`, with
  exactly three R/RX/RW `PT_LOAD` segments, NX stack and RELRO. It intentionally lacks the
  build-id, unwind data, symbol/version tables, alignment choices and linker details of a
  normal compiler output. The profile is specifically glibc/x86-64, not generic Linux.
- **Valid executable-format evidence, not an activation-ready filesystem.** Fixture ABI v2
  binds a logical guest mode of 0755 for current ELF files, but the development carrier stays
  0600 and deterministic releases normalize files to 0644. Parser and native-tool acceptance
  do not imply that a released fixture is executable or installed.
- **Marked.** A named ELF note carries `ARTIFACTFORGE-SYNTHETIC-<16 hex>`.

## desktop-entry

- **Strict XDG naming record only.** One `[Desktop Entry]` group carries Version 1.5,
  `Type=Application`, plain Name/Comment, one normalized absolute `Exec` path with no arguments
  or field codes, and lowercase false Terminal/Hidden/DBusActivatable values. Localized keys,
  actions, `TryExec`, quoting and additional groups are absent.
- **Not proof of working persistence.** The file sits under the modeled user's recursive
  `.config/autostart` export and PyXDG plus the raw reader accept its shape. ArtifactForge does
  not install it or launch a desktop session. Fixture ABI v2 binds the target's logical guest
  mode and causal timestamp but never applies them to the host carrier.
  `desktop-file-validate` is native attestation, not an activation test.
- **Deliberately narrow second reader.** The first-party parser rejects every desktop-entry
  feature outside the emitted subset and never expands or executes `Exec`; it is an independent
  implementation under the same project governance, not general XDG validation.
- **Marked.** `X-ArtifactForge-Synthetic=ARTIFACTFORGE` is an extension key.

## bash-history

- **A record of command text, never proof of execution.** The file uses Bash extended-history
  `#epoch` lines followed by one-line commands. Three exact resident guest paths and one quoted
  `:` no-op marker are synthetic history entries; no claim is made that a shell ran them.
- **Safe, deliberately tiny grammar.** Epochs are positive and strictly increasing. Command
  strings are exact allowlisted resident paths or the marker no-op; arguments, operators,
  pipes, redirection, substitution, multiline records, interpreters, network clients and
  destructive verbs are rejected. ArtifactForge never sources or evaluates the history.
- **Parser scope is loose-file history.** dissect.target and the bounded raw reader agree on
  timestamp, order and command text. The scene has no shell-session metadata, exit statuses,
  terminal context or proof that history writing was enabled on a real host.
- **Marked.** The quoted `: 'ARTIFACTFORGE-SYNTHETIC-LINUX'` history record is inert data and
  the raw profile requires its exact bounded form.

## quarantine-xattr

- **Serialized value or logical manifest metadata, never host metadata.** Scene and benchmark
  builders expose each value as a `.quarantine.xattr` file. Fixture ABI v2 consumes that
  sidecar into a named `com.apple.quarantine` manifest blob on the corresponding guest binary;
  ArtifactForge writes neither a sidecar path nor a host xattr to the declared v2 carrier.
  Incidental host xattrs or ADS values are outside raw-carrier verification, so their absence
  and inertness are not claimed. Neither representation proves that Gatekeeper or
  LaunchServices observed the file.
- **Exact four-field profile.** Only `0181;<eight lowercase hex digits>;<bounded ASCII
  agent>;<uppercase RFC 4122 v4 UUID>` is accepted. A BOM, newline, padding, noncanonical
  timestamp or UUID, extra field or permissive whitespace is red.
- **Two deliberately independent first-party readers.** Gate 1 pairs the artifact module's
  strict parser with a separate byte-level implementation and requires a type-exact field
  match before checking the profile. This is independent implementation under the same
  project governance, not external validation or general xattr support.
- **Not marked; narrowly exempt.** A real quarantine value has no extension field in which to
  carry an `ARTIFACTFORGE` anchor. Gate 3 treats only a strict-valid value as non-executable
  serialized data exempt from its marker requirement; merely using the suffix does not earn
  the exemption.
- **Fixture assurance is a bounded logical join.** V2 assurance presents every manifest xattr
  to both Gate 1 readers and requires type-exact consensus plus the strict four-field profile
  before comparing its UUID set with the `QuarantineEventsV2` row set. This establishes that
  declared relation, not provenance, filesystem application or OS-policy processing; raw host
  xattrs and ADS remain outside the claim.

## Not emitted at all

Disk images, memory dumps, EVTX, ShimCache, TaskCache registry state, Jump Lists, FSEvents and
unified logs are not generated. ArtifactForge targets loose files that responder tools read
directly.

## EvidenceForge coupling

`artifactforge/ef_seeds.py` recovers a Sysmon-local logical identity from EvidenceForge's
seed-derived hash fields by reproducing upstream's private Sysmon seed construction. SemVer
does not protect that surface. The integration is pinned to `v1.13.1`, isolated in one module
that nothing else imports, and absent from public exports. Isolated contract jobs fail rather
than skip when EvidenceForge is missing or its formulas change.

The stock branch-office run has no basename-matched Sysmon/Zeek pair. Recovery from that run is
not evidence that one logical file received inconsistent values across emitters.
