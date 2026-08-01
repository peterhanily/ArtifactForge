# Fixture Core v1

Fixture Core is the stable, public-reproducible side of ArtifactForge. It turns a small JSON
recipe into a self-describing directory of loose forensic artifacts, proves that every byte
matches its manifest and recipe, compares two fixtures, and packages a deterministic release
archive.

It is deliberately separate from the benchmark. A fixture manifest publishes file digests
and embeds its public seed; putting one inside a benchmark scenario would disclose answers.
`benchmark_eligible` is therefore fixed to `false`, and the fixture commands never read or
write benchmark suite layouts.

## Lifecycle

```sh
artifactforge fixture build examples/fixtures/windows-loose-v1.json out/windows
artifactforge fixture verify out/windows
artifactforge fixture verify out/windows --assurance
artifactforge fixture inspect out/windows
artifactforge fixture diff out/windows another/windows
artifactforge fixture release out/windows dist/windows-dropper-001.tar --assurance
```

`build` refuses any existing output path, including a broken symlink. It builds beside the
destination, regenerates the embedded recipe, compares the complete payload, and only then
syncs every generated file and directory and publishes with an atomic no-replace rename. A
failure before publication leaves no output. If the final parent-directory sync fails after
the rename, exit 2 reports `published: true` plus the verified recipe and tree digests: the
output exists and is complete, but crash durability could not be confirmed. There is no
`--force` switch.

`verify` requires canonical manifest bytes, recomputes every size and SHA-256, requires the
recursive inventory to be exact, and regenerates the fixture from its embedded recipe. The
optional `--assurance` additionally runs Gates 1 and 3 over the payload. Missing parser
oracles are failures, not skips. Gate 2 is intentionally absent here: its join truth is not
published in the manifest.

`inspect` verifies before summarising. `diff` verifies both inputs before reporting recipe and
payload differences. `release` verifies first and writes an uncompressed deterministic USTAR
archive with fixed order, ownership, modes and timestamp. One descriptor-pinned byte snapshot
is privately reproduction-verified and supplies the archive bytes; the held archive inode is
then checked through that descriptor and published with a no-replace, inode-bound clone or
link into a pinned destination directory. Unsupported platforms fail closed. Standalone
archive verification also reproduces the embedded recipe, so a canonically rehashed but
non-reproducible archive is red.

Exit code 0 means success (or identical inputs for `diff`); 1 means a meaningful negative
result such as a verification failure or differing fixtures; 2 means malformed input,
unsupported schema/version/ABI, unsafe filesystem state, I/O failure or an existing output.
The post-publication durability case above also exits 2, but is never rendered as an ordinary
failure that could be mistaken for “nothing was written.”

Release publication follows the same rule: if its final directory sync fails after the
verified archive is linked into place, exit 2 reports `published: true` together with the
archive path, SHA-256 and size. The verified archive remains present; only confirmation of
crash durability is missing.

## Contract

The input schemas are `artifactforge-fixture-spec-v1` and
`artifactforge-fixture-manifest-v1`. Both reject unknown fields, duplicate JSON keys,
non-normalised text, floats and unsafe paths. JSON written by ArtifactForge is UTF-8,
sorted-key, compact, no-NaN JSON with exactly one trailing line feed.

Payload paths are printable-ASCII POSIX-relative names. Absolute paths, dot components,
backslashes, control characters, symbolic links, special files and case-fold collisions are
rejected. A tree digest covers the canonical, sorted list of each path, size and SHA-256.

The scene key uses a fixture-specific HMAC domain and never reuses benchmark derivation. The
seed is public by design: fixtures are reproducible QA assets, not secret hold-outs.

The manifest contains no answer key, join record, timestamp, absolute path or machine state.
It identifies the exact package version and byte-affecting generator ABI. Verification v1
requires that exact installed generator version so reproduction never silently substitutes a
different implementation. Schema and ABI remain separate compatibility axes for a future
explicit migration command; any byte-affecting generation change also requires a new ABI.

## Profiles and fidelity boundary

`windows-loose-v1` means exactly what it says: a collection of independently parseable loose
Windows artifacts. It is not a Windows 10 disk image and does not claim one internally
consistent Windows release. In particular, its NT6-era paths coexist with uncompressed SCCA
v17 and the XP/Server 2003 prefetch filename hash. This profile name travels in every recipe
until a v30 writer and deterministic MAM/LZXPRESS compression exist.

`macos-14-loose-v1` emits the current arm64 Mach-O, SQLite databases, LaunchAgent plists and
quarantine sidecars. The SQLite and plist independent-oracle gaps remain disclosed in the
fidelity scorecard.

## Integrity is not authenticity

The manifest and archive detect changes and reproduce exact bytes. They are not signed and do
not authenticate who created them. Release source provenance remains the clean Git-bound
scorecard and the repository tag; Fixture Core does not turn a self-reported digest into an
identity claim.
