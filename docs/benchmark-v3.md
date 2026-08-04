# Benchmark v3 evaluator ceremony

## Status

Benchmark v3 is a distinct protocol, not a reinterpretation of Benchmark v2. It provides:

- evaluator-created local freshness evidence;
- a v3-only submission precommitment;
- one designated local attempt ledger;
- a receipt that withholds score feedback;
- irreversible retirement within that ledger; and
- detached verification of the report's internal consistency.

These are local controls. The private result remains plaintext to the ledger owner, and the
protocol cannot stop that owner from communicating with the solver or copying local state. It
does **not** produce a reportable performance result. A reportable run still needs an
independently witnessed, uniquely designated ledger and an OS-enforced solver trust domain.

The public reportability value is `eligible-pending-external-attestation`. "Eligible" means
only that the suite came from the v3 constructor and passed its local structural checks. The
in-band trust statement calls this **local self-attestation only**. It does not attest evaluator
independence, solver isolation, unique ledger designation, key non-disclosure or an external
witness.

Benchmark v2 remains parseable at `artifactforge-benchmark-public-v2` and
`artifactforge/bench/v2`. Every v2 suite, including one labeled `holdout`, is classified
`permanently-ineligible` because its raw key was caller-supplied and no freshness ceremony was
recorded.

## Creating an evaluator ceremony

```sh
artifactforge bench ceremony create EVALUATOR --n 120
artifactforge bench export EVALUATOR PUBLIC
```

### Ceremony inputs

The Python constructor is `create_evaluator_ceremony(n, root)`. It has no key, ceremony ID,
timestamp, origin or reportability parameter. It obtains 48 bytes from
`secrets.token_bytes`: 32 bytes become the private suite key and 16 bytes become the random
`afc1_...` ceremony identifier. The timestamp is canonical UTC with six fractional digits.

### Population contract

V3 accepts only even populations from 120 through 200. The zero-based parity schedule then
provides at least 60 Windows and 60 macOS scenes, satisfying the population bound carried by
the theoretical sparse-power contract. Construction does not itself execute Gate 4 or provide
per-suite evidence that an attack/control measurement ran. The CLI default is 120. Legacy v2
local diagnostics retain their 1–200 range and existing defaults.

### Publication

The command publishes a new evaluator directory only. It never prints the key. A destination
that is already a file, directory or symlink is refused without modification. Concurrent
creators can stage independently, but the descriptor-bound no-replace publication permits
exactly one winner and removes the losing private stage.

## Public origin and suite identity

The v3 public document uses schema `artifactforge-benchmark-public-v3` and derivation domain
`artifactforge/bench/v3`. Its exact `origin` object contains:

- schema and mode identities;
- the ceremony ID and canonical creation time;
- `python-secrets-token-bytes/os-csprng` as the entropy-source identity;
- a domain-separated SHA-256 commitment to the private key;
- the exact protocol object, whose `population_power_contract` member binds the theoretical
  39-comparison, `1/780` Bonferroni calculation, two named alternatives, 60-scenes-per-family
  minimum and 120–200 even-population bounds;
- `eligible-pending-external-attestation`; and
- the local-self-attestation limitation.

The exact path is `origin.protocol.population_power_contract`. It contains theoretical protocol
and population/power data, not a Gate 4 result for this suite. `suite_id` hashes the complete
canonical public document without its own field, binding the origin, questions, scenario tree
commitment and export metadata.
Changing the origin while retaining the old ID is rejected. The commitment is
`SHA256("artifactforge/bench/v3/key-commitment/v1" || NUL || key)` and is checked against the
held key whenever the evaluator is loaded.

Unknown fields, alternate modes, invented reportability values, changed protocol identities,
non-canonical timestamps and mismatched key commitments fail closed. A local writer who owns
both the key and evaluator directory can construct new self-consistent bytes. The record is
therefore not independent attestation.

## Private record and filesystem boundary

The private evaluator adds one exact record:

```text
EVALUATOR/
  public.json                    0600
  scenarios/...
  _key/key.hex                  0600
  _ceremony/                    0700
    ceremony.json               0600
  _answers/...
  _content/...
```

`ceremony.json` uses schema `artifactforge-benchmark-ceremony-private-v1`. Its remaining fields
must equal the public origin exactly. The loader parses canonical, duplicate-free, float-free
JSON; rejects unknown fields and records over 16 KiB; checks the key commitment and ceremony
ID; and requires exact private modes on POSIX. Generation explicitly sets modes even under a
hostile `umask`.

Evaluator capture opens the ceremony directory and record without following links, binds
directory entries to held descriptors, checks the exact one-file inventory, and compares file
identity and bytes across the capture. Symlinks, special files and same-byte inode replacement
are rejected. The public export contains the bound public origin but never `_ceremony`, `_key`,
answers or content-cache state.

## One-shot submission and local attempt ledger

The v3 evaluator refuses the repeat-feedback `bench grade` path. The solver instead writes one
canonical, scenario-ordered JSONL reveal and commits it before the evaluator accepts any
submission:

```sh
# Solver trust domain; PUBLIC is the only transferred evaluator material.
artifactforge bench solve PUBLIC --out submission.jsonl
artifactforge bench precommit PUBLIC submission.jsonl --out precommit.json \
  --implementation-sha256 sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  --configuration-sha256 sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \
  --source-sha256 sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc

# Evaluator trust domain. LEDGER must be a new private directory outside EVALUATOR.
artifactforge bench attempt accept EVALUATOR precommit.json LEDGER
artifactforge bench attempt consume EVALUATOR LEDGER submission.jsonl
artifactforge bench attempt retire LEDGER
artifactforge bench attempt report LEDGER > retired-report.json
artifactforge bench attempt verify retired-report.json --reveal submission.jsonl
```

### Precommitment

The precommitment binds `suite_id`, the exact reveal SHA-256 and size, canonicalization
identity, and three labelled solver digests. Those solver digests are caller assertions, not
attestations. Precommitment creation validates the complete v3 public origin and explicitly
rejects every legacy v2 export, rather than creating a record that no v3 ledger can accept.
`bench solve` and `bench precommit` pin the exact public-export inode while validating it and
reject output parents inside that export, including case aliases and parents moved across the
boundary during publication.

### Ledger acceptance

`attempt accept` takes an evaluator path, never an in-memory public dictionary. It invokes the
authoritative full v3 loader, accepts only the suite ID that loader derives, and atomically
publishes a new mode-0700 designated ledger containing exact mode-0600 acceptance,
precommitment and lock records. The local API keeps the ledger outside the evaluator by
held-directory inode ancestry, not lexical path spelling, and rechecks that boundary during
consumption. It cannot inspect whether the solver ran in a separate account, container/VM or
machine; that trust-domain isolation is an orchestration property.

### Consumption and crash recovery

`attempt consume` acquires a crash-released process lock for the complete state transition. It
atomically publishes a complete no-replace claim **before opening the reveal**. An absent,
unreadable, noncanonical, wrong-suite or digest-mismatched reveal therefore consumes the one
local attempt just like a scored reveal. Detailed validity and score data are stored as
plaintext in mode-0600 `result.private.json`, so the ledger owner can read them. A random
`blinding_nonce` makes the result hash computationally hiding to a recipient who receives only
the returned hash-linked receipt; that receipt contains no score, validity or success bit. This
is receipt-level feedback withholding, not encryption or enforcement against the ledger owner.
A concurrent consumer or retirement cannot cross the active transition.

Stage recovery is deliberately conservative. At the next locked transition, a stage with no
final record is discarded whether or not its bytes were complete; it is never promoted. If the
final record already exists, the leftover stage must be a second hard link to that exact inode
before the stage link is removed. Thus an already published claim survives a crash and prevents
replay, while an unpublished stage cannot become a new protocol record during recovery.

### Records and retirement

Claim, result, receipt and retirement records are canonical, self-bound and hash-linked. Their
carrier type, inode, size, link count and private mode are checked on held descriptors, and
their states, timestamp format/order, suite/attempt identities, submission commitment, internal
score arithmetic, outcome, nonce, notices and trust wording are validated before retirement. A
record with a recomputed self-hash but an invalid internal contract is rejected. These checks do
not establish that the scenario/question identities or expected answers came from an authentic
evaluator.

Retirement is irreversible only within the designated local ledger: the API will not consume or
retire that root again, while a local owner can still copy, delete or rewrite filesystem state.
Retirement is allowed before any claim and after a crash at any later complete prefix. A retired
report always contains acceptance, precommitment and retirement. Its optional records may have
only one of these complete prefixes:

- none;
- claim only;
- claim plus result; or
- claim, result and receipt.

Before retirement, the report API withholds the detailed result while the plaintext file
remains visible to the ledger owner. After retirement, `attempt report` returns the canonical
self-bound bundle, reveal digest and size, disclosed outcome and detail, and the complete local
trust warning.

### Detached verification

The portable `bench attempt verify` command and Python `verify_retired_report` API check the
canonical report self-hash, complete-prefix and record-link structure, allowed internal
states/timestamp ordering, score arithmetic and disclosure agreement. With `--reveal` they also
check the exact committed reveal size and digest. They receive no evaluator root or public
suite, do not authenticate the ceremony or its producer, do not validate scenario/question
inventories or answer truth, and do not regrade the reveal. An author who controls all detached
inputs can create a different internally self-consistent chain. Every report states
`reportable: false`, `eligible-pending-external-attestation` and **NOT REPORTABLE**. Retirement
releases local feedback; it does not turn a local filesystem chain into an independent witness.

## Resource bounds

| Surface | Limit |
|---|---:|
| V3 population | even, 120 through 200 scenarios |
| `public.json` | 16 MiB |
| recursive public capture | 4,096 files and 256 MiB |
| public files at 200 scenarios | 3,001 |
| canonical reveal | 16 MiB total |
| one JSONL line | 1 MiB |
| reveal rows | 200 |
| one scalar answer | 4,096 characters |
| precommitment or ceremony record | 16 KiB each |
| one stored live-ledger record | 4 MiB |
| detached report input | 32 MiB |

These are independent denial-of-service ceilings. They do not permit every maximum to be
allocated at once and say nothing about benchmark difficulty.

## Host support

Live ledgers require `os.name == "posix"`, the exact `os.supports_dir_fd` operation set,
descriptor directory inventories, directory durability sync and advisory locking. ArtifactForge
checks those capabilities before live mutation rather than treating every nominally POSIX host
as sufficient. Python documents that `dir_fd` parameters currently work only on Unix, not
Windows. The Ubuntu test matrix and native macOS 14 CI exercise the live lifecycle. Windows CI
asserts that accept/consume/retire/report fail closed and exercises canonical submission,
v3-only precommitment and detached-verifier paths. Detached retired-report verification remains
portable because it does not open or mutate a live ledger. See the
[Python `os.supports_dir_fd` contract](https://docs.python.org/3/library/os.html#os.supports_dir_fd).

## Remaining reportability work

The ceremony closes raw-key relabeling, and the designated ledger prevents a second API claim
within one intact root while withholding feedback from the returned receipt. Neither prevents
the ledger owner reading the plaintext private result, nor proves that the evaluator did not
copy the suite, accept the same precommitment into multiple roots, delete or rewrite local
state, expose private files to the solver, or withhold a retired report. A
reportable run still requires:

1. an OS-enforced solver account/container/VM/machine that receives only the exact public
   export and cannot access the evaluator or ledger;
2. an independent witness that binds the ceremony, source/export identity, solver image and
   configuration, isolation policy, accepted precommitment, uniquely designated ledger and
   terminal evidence bundle; and
3. a publication policy that preserves that witness and the detached verifier inputs without
   disclosing the key or evaluator answers before retirement.

Until those conditions are implemented and exercised, every v3 report is protocol-development
evidence only, even when it scores 100% and every local validation passes.
