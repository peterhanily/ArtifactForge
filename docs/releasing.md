# Release evidence and attestation

ArtifactForge does not currently have an automated package-publication path. The release tools
prepare and inspect exact distribution bytes, exercise a credential-free publish dry run, and
optionally let an approved GitHub Actions run attest those bytes. They do not create or push a
tag, create a GitHub release, or upload a package to PyPI.

## Current state

The current source contains the complete Phase 5 release implementation. A settled-tree local
diagnostic established all of the following:

- two hostile-environment builds were byte-identical;
- source preconditions and postconditions held while the evidence was created;
- closed/offline and repository-refreshed verification passed;
- all three SBOMs passed the official schema closure;
- the private-copy uv loopback rehearsal completed; and
- the exact wheel installed, reported its version and compiled without dependencies.

That diagnostic used the explicit dirty-source override. It is source-bound non-release
evidence, not a clean tagged-release rehearsal. The first protected hosted release-attestation
remains pending. Hosted schema-v6 Windows-native runs produced diagnostic failure evidence;
hosted schema-v7 run 30944614694 recorded the first complete passing native result.

## Claim boundary

| Evidence | What it establishes | What it does not establish |
|---|---|---|
| `release-evidence.json` and `checksums.txt` | A closed local bundle passed the recorded source, archive, distribution-chain, SBOM and digest checks | Producer/build-host identity, a signature, package publication or a reportable security result |
| Runtime and development CycloneDX documents | The normalized locked dependency graphs match ArtifactForge's exact release profiles; the runtime graph is empty | Independent authorship, vulnerability status or host-wide network isolation |
| `scripts/publish_rehearsal.py` | The exact canonical wheel and sdist are accepted by the fixed `uv publish` dry-run command | Authentication to, contact with or upload to PyPI |
| `.github/workflows/release-evidence.yml` | After a successful approved run, GitHub attestations bind the selected tag run to exact subjects and SBOMs | The workflow file alone provides no protection; the workflow does not publish a package or GitHub release |

The local manifest deliberately classifies itself as `local-self-attestation`, with external
authentication, command signing, package publication and reportable-security-result fields all
false. Its digests are cryptographic digests of the real bytes; they are not signatures.

## Local rehearsal

### Requirements and commands

Use exactly uv 0.11.17 and a clean worktree for release-candidate evidence. The explicit
`--allow-dirty` option exists only for a source-bound non-release diagnostic. The output path
must not already exist and must be outside the repository.

```sh
release_root="$(mktemp -d)"

uv python install 3.12.13
uv sync --frozen --extra dev --python 3.12.13

umask 022
PYTHONHASHSEED=1 TZ=UTC LC_ALL=C SOURCE_DATE_EPOCH=1580601600 \
  uv build --no-sources --no-create-gitignore \
    --build-constraint build-constraints.txt --require-hashes \
    --out-dir "$release_root/dist-a"

umask 077
PYTHONHASHSEED=7 TZ=Asia/Tokyo LC_ALL=C SOURCE_DATE_EPOCH=1580601600 \
  uv build --no-sources --no-create-gitignore \
    --build-constraint build-constraints.txt --require-hashes \
    --out-dir "$release_root/dist-b"

uv run python scripts/release_evidence.py create \
  --primary-dist "$release_root/dist-a" \
  --comparison-dist "$release_root/dist-b" \
  --out "$release_root/evidence"

uv run python scripts/release_evidence.py verify \
  "$release_root/evidence" --repository-root "$PWD"

.venv/bin/python scripts/publish_rehearsal.py "$release_root/evidence/dist"
```

### Evidence creation

Creation requires two separately supplied distribution directories and rejects the same root,
the same file inodes, non-canonical names, extra entries, links, special files and byte drift.
The source inspector establishes cleanliness with a fixed system Git executable and no ambient
configuration, routing or replacement objects. It parses the HEAD and index inventories, then
hashes the tracked worktree bytes and modes plus untracked content. The resulting commit, tree
and required release-material records are bound into both the evidence and distribution chain.

Creation also checks exact wheel ZIP and sdist gzip/USTAR profiles,
source-to-sdist-to-wheel bytes and modes, metadata and entry points. It then publishes a closed
evidence directory without replacement. The descriptor-bound publication and
directory-durability contract is currently
POSIX-scoped; the release workflow deliberately runs it on Ubuntu. Do not infer a supported
Windows release-evidence path from the portable verifier tests or from the separate Windows
artifact-attestation lane.

### Verification

Verification without `--repository-root` rechecks the closed bundle, its archive profiles,
distribution chain, SBOM profiles, checksums and exact inventory. Supplying the repository root
additionally requires the current source snapshot to match and regenerates the runtime and
development SBOMs with uv using `--offline --locked --no-config --no-sources` in a private
cache and minimal child environment. That closes uv's configured dependency-resolution path;
it cannot prove that no other process or host facility used the network.

### SBOM schema closure

The workflow downloads the three official CycloneDX 1.5 schema resources from upstream commit
`c320fc0f0b46873864927d9d5684eea7ba439728`, verifies their reviewed SHA-256 digests, and runs
the validator with a closed local schema registry:

| Schema | SHA-256 |
|---|---|
| `bom-1.5.schema.json` | `067f7824b08653839ea050ae9e09ca48375eadc2652b0e2a299476e7db90335b` |
| `jsf-0.82.schema.json` | `8bae002c25e723db7ee1f26afde680ae1a2b1a8f6b4b4b0fd65dc3becb090aae` |
| `spdx.schema.json` | `4f6e2b05c05d26a4f2dc5879fbc2fca94b0a28db46289d0c51345621b71cfbfc` |

### Publish dry run

`scripts/publish_rehearsal.py` takes no caller-supplied index or extra uv flags. It copies the
reviewed uv executable and the exact two distributions into a private directory, drops ambient
credentials, proxy, uv configuration, keyring, OIDC and loader variables, and fixes the command
to `--no-config --dry-run --trusted-publishing never --keyring-provider disabled` against
`http://127.0.0.1:9`. Success proves only the local dry-run command path.

## Protected hosted attestation

### Preconditions

Before the first run, repository administrators must configure the `release-attestation`
environment with the required reviewers/protection and configure the intended tag protections.
Declaring the environment in YAML does not configure or protect it.

The manual workflow will run only from a `refs/tags/v...` reference. It requires an exact
annotated tag whose name is `v` plus the version in `pyproject.toml`, whose target is the
selected `GITHUB_SHA`, and whose checkout is clean. Creating and pushing that tag is a separate,
approval-gated operator action; the workflow cannot do it.

### Workflow

After approval, the workflow:

1. Checks out the exact tag without persisted credentials on fixed `ubuntu-24.04`.
2. Installs uv 0.11.17 from the platform wheel hashes in
   [`ci-bootstrap-requirements.txt`](../ci-bootstrap-requirements.txt), then installs the locked
   release/tooling closure.
3. Runs the release protocol tests, performs two hostile-environment builds, installs the exact
   wheel without dependencies, and executes one Fixture Core build/verify smoke.
4. Creates and independently verifies the local evidence bundle, validates all three SBOMs
   against the hash-pinned official schemas, and runs the loopback publish rehearsal.
5. Uses the immutable-pinned `actions/attest` action to attest both distributions, the wheel and
   sdist runtime SBOMs, the local manifest/checksums, and the development-oracle SBOM.
6. Retains the exact local bundle as a workflow artifact.

### Permissions and network

The attestation steps are external repository mutations backed by GitHub OIDC/Sigstore. The
workflow has `id-token: write`, `attestations: write` and `artifact-metadata: write` only in its
single job. Bootstrap, dependency installation and schema download may contact their configured
package or source hosts. The workflow never invokes a non-dry-run publish command, uploads or
publishes a package to PyPI, pushes a tag, or creates a GitHub release. A real protected
successful run is required before describing any subject as hosted-attested.

### Action and runner pins

All third-party actions are pinned by immutable commit. Dependabot may propose reviewed updates
to those pins; it does not make an update trustworthy or merge it automatically. The hosted
runner labels are also explicit (`ubuntu-24.04`, `macos-15`, and
`windows-2025-vs2026`), but a label is not an immutable machine image. Retained host and tool
evidence therefore remains part of each native claim.

| Action | Reviewed release | Immutable commit |
|---|---|---|
| `actions/checkout` | v6.0.2 | `de0fac2e4500dabe0009e67214ff5f5447ce83dd` |
| `actions/upload-artifact` | v7.0.1 | `043fb46d1a93c77aae656e7c1c64a875d1fc6a0a` |
| `actions/download-artifact` | v8.0.1 | `3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c` |
| `actions/attest` | v4.2.1 | `508db95dd578ae2727ebd6217d5ba78e4fbda05d` |

## Runtime compatibility

### Python support

The full parser-oracle test matrix remains CPython 3.11, 3.12 and 3.13. The CPython 3.14 lane is
intentionally core-only: it binds the running CPython, builds and installs the zero-runtime-
dependency wheel without dependencies, compiles the installed package, and builds/verifies all
three Fixture ABI v2 families. It does not promote the full development-oracle closure. The
reviewed lock is `known_blocked` on CPython 3.14 by `dissect-target==3.25.1` (runtime import) and
`yara-python==4.5.4` (no reviewed CPython 3.14 binary distribution). A future dependency change
must trigger target installation, imports, positive controls and behavioral tests; metadata or
wheel tags alone are not promotion evidence.

### Windows-native evidence

The Windows-native implementation prepares a byte-bound portable prerequisite on Ubuntu and
observes private copies on `windows-2025-vs2026`. It authenticates PowerShell, `vswhere.exe`
and the selected x64 `link.exe`. PE inspection calls the real parser directly as
`LINK /DUMP /NOLOGO /NOPDB /HEADERS`. A
[Microsoft implementation note](https://devblogs.microsoft.com/oldnewthing/20240617-00/?p=109905)
identifies this as the engine behind `dumpbin.exe`, so the wrapper is not part of the trust
boundary. The observer removes LINK option and repro environment controls before each call.

The Authenticode positive control is the same PowerShell 7 executable already bound as a
native tool. Python first verifies its Microsoft signature through WinVerifyTrust. PowerShell's
`Get-AuthenticodeSignature` result must name the same signer certificate, and
`Get-FileHash` must reproduce the recorded SHA-256. The control and tool records must carry the
same identity and remain unchanged. `IsOSBinary` is retained as descriptive evidence only; it
indicates OS-release membership, not whether a signature is valid.

Target-bearing PowerShell observations require version 7.5 or later and use
`-CommandWithArgs`, so literal paths stay separate from PowerShell source. Fixed numeric
VERSIONINFO records bind `vswhere.exe` and `link.exe` to their already hashed and authenticated
bytes. The PowerShell command version must agree with the in-process `$PSVersionTable`
observation. No emitted PE is executed. A successful hosted Windows run is still required
before making a native acceptance claim; unit and mutation tests on another host do not
substitute for that observation.
