# EvidenceForge relationship

EvidenceForge is not a runtime or development dependency. ArtifactForge includes an isolated
adapter and contract tests for its synthetic log model. The distribution name is
`evidence-forge`; the import name is `evidenceforge`.

On a fresh, unmodified EvidenceForge v1.13.1 `branch-office-example` run, the adapter observed
**7 hosts, 853 Sysmon records carrying SHA256, all 853
recovered and verified** against the hashes EvidenceForge emitted, resolving to 105
distinct Sysmon logical identities. The verified seed forms were `from_host_metadata` for 78
identities and `with_description` for 27. Event ID 1 gives 614 records and 78 distinct
SHA1/SHA256 values.

The same run's Zeek `files.json` has 722 rows: 525 certificate and 197 non-certificate rows,
with 119 distinct SHA1 and 103 distinct SHA256 values overall. The same-algorithm Sysmon and
Zeek sets are disjoint, but their basenames are also disjoint. That stock scenario therefore
shows separate emitter-local identity domains, not a controlled same-file mismatch.

A separate controlled scenario models one HTTP download to an exact path followed by execution
of that path. It includes same-name and unrelated-path controls and shows that the Zeek and
Sysmon seed formulas do not join for that modeled logical file. This is a relationship between
modeled events, not proof of shared materialized file bytes.

The source records and upstream-ready material are in
[`../measurements/`](../measurements/) and
[`../integration/evidenceforge/`](../integration/evidenceforge/). I posted a
[follow-up on EvidenceForge #332](https://github.com/Cisco-Talos/EvidenceForge/issues/332#issuecomment-5152265897)
mentioning this work. I have not opened a formal issue or pull request from the local drafts.

To run the pinned contract locally:

```sh
uv pip install "evidence-forge @ git+https://github.com/Cisco-Talos/EvidenceForge@v1.13.1"
uv run python -m evidenceforge generate \
  integration/evidenceforge/scenarios/content-identity-witness-v1.13.1.yaml -o ef-out
ARTIFACTFORGE_EF_OUT=ef-out uv run pytest -q tests/ef_contract/
```

ArtifactForge does not depend on EvidenceForge at runtime or to build. This page records
what was measured between the two projects and what it does and does not establish.
