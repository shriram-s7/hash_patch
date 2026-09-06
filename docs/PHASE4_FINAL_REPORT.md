# Phase 4 — Deployment Topology Exposure (IaC Enrichment): Final Report

Hash Patch (प्रत्यक्ष) · Smart India Hackathon 2026 · PS 26164 (NTRO)
Phase 4 deliverable: deterministic `UNKNOWN/INTERNAL/EXTERNAL/MIXED` exposure
classification of crypto findings from statically parsed Kubernetes + Terraform.

All results below are from the final validation run (2026-09-06).

---

## 1. Executive Summary

Phase 4 adds IaC / deployment-topology **enrichment** to Hash Patch. Existing
crypto findings are matched to the workloads that ship them (via container
image / digest identity), then walked through the service / ingress / gateway /
Terraform topology that fronts them. Each finding is deterministically
classified into one exposure state — `EXTERNAL`, `INTERNAL`, `MIXED` —
and, when no topology can be evidenced, the brutally honest `UNKNOWN`. The
classification is provably **not** an LLM verdict: it is computed by the
`detect/iac/*` code path, serialized verbatim into the CycloneDX 1.6 CBOM
under the `hash_patch:` namespace, and surfaced in the Q&A grounding, the
Ollama evidence package, and every UI report surface.

No existing formula was touched: quantum status, call-graph reachability,
blast-radius, and migration scoring are byte-identical to Phase 3. Phase 4 is
additive metadata, and the full unit + golden suites pass with zero regressions.

## 2. Objective & Scope (hard boundaries)

- **In scope.** Statically parse committed Kubernetes manifests (YAML) and
  Terraform (HCL / `tf.json`); correlate crypto findings → workloads →
  services → ingresses/gateways → Terraform resources; classify exposure;
  emit as CBOM properties; route `IAC_EXPOSURE` Q&A; surface in UI.
- **Not in scope (deliberately).** No live probing, `kubectl`/`terraform`
  execution, no CVE / misconfig / IAM / secret scanning, no network calls.
- **Hard facts.** `containerPort` / `NodePort` / `EXPOSE` alone never proves
  exposure. Relationship integrity (workload → service → ingress/loadbalancer)
  must be explicitly preserved or the answer is `UNKNOWN`.
- **Determinism.** Same input ⇒ byte-identical CBOM (only the scan timestamp
  varies), enforced by the existing CI determinism tests plus the new
  `test_iac_qa.py::test_input_always_grounded_deterministically`.

## 3. Method — Kubernetes & Terraform parsing

- `detect/iac/kubernetes.py`, `detect/iac/terraform.py`: both parse to the
  shared neutral `IacScanResult` model (workloads, services, ingresses,
  gateways, TF resources, namespaces, parse errors).
- **Namespace is part of resource identity.** A Service in `production` can
  never select a Workload in `staging`, even with matching labels — label
  selectors are namespace-scoped (models.py `Service.matches_workload`).
- **Oversized inputs degrade gracefully.** A file over the configured limit
  (50MB k8s, 10MB terraform) records a `parse_errors` entry and the scan
  continues; it never aborts the run.
- **`tf.json` robustness.** `resource`/`module` blocks arrive as a dict in
  `tf.json` but a list in HCL — `_parse_document` normalizes both shapes
  before walking them.

## 4. Method — Asset → Workload correlation

`detect/iac/correlation.py` derives an `ImageIdentity` (repository, tag,
digest) from the asset's `containerImage`/`imageDigest` properties, then
resolves a workload by deterministic precedence:

1. **Digest match** — strongest, `DIRECT`.
2. **Exact tag match** — `STRONG`.
3. **Name-only repository match** — weakest, `MODERATE`, tag set to `None`.
4. A workload that pins a **different digest or tag than the asset** is a
   **MISMATCH and is rejected — never fuzzy-matched**.
5. Bare `payment-api` ⇒ tag `None`, **never** an implicit `latest`.

Correlation strength and the full evidence chain are emitted, e.g.

```
Workload: kubernetes:production:Deployment:payment-api
 -> Service: kubernetes:production:Service:payment-api-internal (ClusterIP)
 -> Service: kubernetes:production:Service:payment-api-external (LoadBalancer)
 -> Ingress: kubernetes:production:Ingress:payments (payments.example.com)
```

## 5. Method — Exposure classification

Per workload, all selecting services and their reachable ingresses/gateways
are examined; `classify_service_exposure` /
`classify_ingress_exposure` / `classify_gateway_exposure` / `classify_tf_exposure`:

| Signals | State |
| --- | --- |
| `LoadBalancer`, `NodePort`, ingress host, internet-facing TF ALB, AGW listener | `EXTERNAL` |
| `ClusterIP` only, internal-only TF | `INTERNAL` |
| Both an internal and an external path | `MIXED` |
| No workload correlated, or no topology evidenced at all | `UNKNOWN` |

Terraform resources attach as **evidence only** when the asset already
resolved to a workload; otherwise the classification stays `UNKNOWN` — TF
exposure is never used to conjure a workload into existence.

## 6. CBOM representation

No standard CycloneDX field exists for deployment exposure, so (consistent
with the project's field-mapping policy) structured metadata is emitted under
the `hash_patch:` namespace on each enriched component:

- `hash_patch:exposureState` (`external | internal | mixed | unknown`)
- `hash_patch:correlationStrength` (`direct | strong | moderate | weak | none | unresolved`)
- `hash_patch:workload`, `hash_patch:service`, `hash_patch:serviceType`,
  `hash_patch:ingress`, `hash_patch:ingressHosts`, `hash_patch:gateway`,
  `hash_patch:namespace`, `hash_patch:tfResources`
- `hash_patch:evidenceChain` — the canonical, joined chain.

Resource identities always use the deterministic `identity.key()` form
(`kubernetes:production:Deployment:payment-api`), the same string the Q&A
index and report read.

## 7. CBOM example (from `hash_patch-ui/public/fixtures/demo_iac_exposure.cbom.json`, emitted by the real pipeline)

```json
{
  "bom-ref": "crypto-asset:2b23217f4c605672f3ad9c7d021aabde",
  "cryptoProperties": {
    "algorithmProperties": { "primitive": "signature" },
    "assetType": "algorithm"
  },
  "name": "RSA",
  "properties": [
    { "name": "hash_patch:confidence", "value": "confirmed" },
    { "name": "hash_patch:correlationStrength", "value": "strong" },
    { "name": "hash_patch:evidenceChain",
      "value": "Workload: kubernetes:production:Deployment:payment-api -> Service: kubernetes:production:Service:payment-api-internal (ClusterIP) -> Service: kubernetes:production:Service:payment-api-external (LoadBalancer) -> Ingress: kubernetes:production:Ingress:payments (payments.example.com)" },
    { "name": "hash_patch:exposureState", "value": "mixed" },
    { "name": "hash_patch:ingress", "value": "kubernetes:production:Ingress:payments" },
    { "name": "hash_patch:ingressHosts", "value": "payments.example.com" },
    { "name": "hash_patch:namespace", "value": "production" },
    { "name": "hash_patch:service", "value": "kubernetes:production:Service:payment-api-internal" },
    { "name": "hash_patch:serviceType", "value": "ClusterIP" },
    { "name": "hash_patch:workload", "value": "kubernetes:production:Deployment:payment-api" }
  ]
}
```

The demo fixture is validated against the vendored CycloneDX 1.6 schema
(`validate_cbom` passes) and is loadable in the UI via "Load an existing
CycloneDX 1.6 CBOM document".

## 8. Files changed

Backend:
- `hash_patch/detect/iac/models.py` — canonical `key()` identities in `to_properties()`.
- `hash_patch/detect/iac/kubernetes.py` — parsed workloads/services/ingresses/gateways; oversized-file graceful errors.
- `hash_patch/detect/iac/terraform.py` — HCL + `tf.json` parsing, dict→list normalization, oversized-file graceful errors.
- `hash_patch/detect/iac/correlation.py` — identity matching, evidence chains, TF-as-evidence-only rule.
- `hash_patch/detect/iac/scanner.py` — `scan_iac_directory`, `apply_iac_enrichment`, `get_exposure_summary` (canonical keys).
- `hash_patch/qa/index.py` — `findings_by_exposure_state` buckets + `external/internal/mixed/unknown_exposure` accessors.
- `hash_patch/qa/query.py` — `IAC_EXPOSURE` intent keywords extended (`mixed`/`exposure`/`unknown exposure` filter routes).
- `hash_patch/qa/retriever.py` — `_handle_iac_exposure` inventory + `has_topology_evidence` honesty guard (Q9 fix).
- `hash_patch/qa/ollama_client.py` — exposure aggregation line + per-finding IaC fields in the evidence package.

UI (`hash_patch-ui`):
- `src/cbom/types.ts` — `ExposureState` + new `CorrelationStrength` type.
- `src/cbom/cbomToFindings.ts` — `asCorrelationStrength`/`asExposureState` safe parsers.
- `src/DetailPanel.tsx` — Deployment Topology Exposure section + badge (was previously import-only).
- `src/FileCodeView.tsx` — `ExposureBadge` in selected-finding cluster, hover tooltip exposure line, detail-panel topology evidence section.
- `src/RepositoryView.tsx` — per-folder exposure summary + `ExposureBadge` in folder header and every finding card.
- `src/ReportView.tsx` — `ExposureSection` (state count cards, namespace table, workload evidence-chain table, determinism note), on-screen Section 6.5 "Deployment Topology Exposure", PDF page `pdf-page-8`.
- `src/reportPdf.ts` — `PAGE_COUNT` 7 → 8.
- `public/fixtures/demo_iac_exposure.cbom.json` — new real-pipeline demo fixture.

## 9. New test fixtures

- `testdata/iac/kubernetes/` — `internal`, `loadbalancer`, `ingress`,
  `mixed`, `unresolved`, `negative`, `namespaces` (cross-namespace isolation),
  `prompt_injection`.
- `testdata/iac/correlation/` — `container_to_deployment`, `digest_match`,
  `mismatch` (digest/tag mismatch rejection).
- `testdata/iac/terraform/` — `alb` (internet-facing ALB as evidence-only),
  `prompt_injection`.
- Security fixtures — 55MB oversized YAML, YAML bomb, secret-laden manifests,
  path-traversal / symlink targets, prompt-injection payloads.

## 10. New Phase 4 test suites — results

Five suites, **67 tests, all passing** (dependency-free, deterministic):

| Suite | Tests | What it proves |
| --- | --- | --- |
| `test_iac_parsing.py` | 13 | HCL/`tf.json` shape robustness, exposure-relevant attribute handling |
| `test_iac_correlation.py` | 15 | Image identity, digest>tag>name precedence, mismatch rejection, TF-as-evidence-only, cross-namespace isolation |
| `test_iac_exposure.py` | 16 | Per-fixture state classification + CBOM emission + `get_exposure_summary` |
| `test_iac_security.py` | 13 | Malformed inputs, oversized files, YAML bomb (no crash), secrets never leak into properties, prompt-injection inertness, path traversal/symlink safety |
| `test_iac_qa.py` | 10 | Index classification, `IAC_EXPOSURE` routing (incl. new `mixed` route), evidence-chain surfacing, determinism, honest UNKNOWN fallback, Ollama serialization of exposure fields |

## 11. Security test results

- **Oversized input (55MB YAML)**: recorded as a `parse_errors` entry; scan
  continues; no exception, no abort.
- **YAML-bomb (aliases blowing up memory)**: parsed safely; no denial of
  service on the scan path.
- **Secret safety**: marker secrets placed in manifests are treated as inert
  data — they never appear in any property, evidence card, or output blob
  (`hash_patch:exposureState`/evidence chains stay secret-free).
- **Prompt injection** (malicious instruction strings in deployment names /
  service annotations / TF resource names): the retriever treats IaC fields as
  untrusted **data**, and the Ollama system prompt carries the explicit
  "UNTRUSTED DATA" framing; classification never honours injected directives.
- **Path traversal / symlink targets**: scanner resolves paths safely, never
  escapes the target root.
- All 13 `test_iac_security.py` assertions pass.

## 12. Regression results

- **14 canonical manual Q&A** (Phase 3 acceptance) all still route and answer
  correctly on the `test2` corpus with Phase 4 in the loop (see §16).
- **Q9 honesty guard** (the Phase 4 fix): a container-only target answers
  "Is the RSA in this container externally exposed?" with the topology
  inventory's explicit `UNKNOWN` verdict, e.g.:

  ```
  DEPLOYMENT TOPOLOGY EXPOSURE INVENTORY
  No IaC / deployment topology evidence was found for scan target 'scan'.
  All 27 cryptographic operations therefore default to exposure state UNKNOWN.
  Reachability is UNKNOWN. Static container image inspection does NOT prove external network exposure.
  ```
- **Container regression guard in tests**: `test_iac_qa.py::TestContainerExposureStaysHonest`
  asserts a mock whose image does not match the correlated workload stays
  `UNKNOWN` and never emits a fabricated "external" verdict.
- No change to `risk_score`, reachability multipliers, or migration cost
  formulas — verified by the unchanged golden suite and the full regression path below.

## 13. Full test suite

```
tests/unit/   599 passed, 15 skipped  (72.94s)   — includes all 67 new Phase 4 tests
tests/golden/ 135 passed,  2 skipped  (3.63s)
```

The 15 unit skips and 2 golden skips are all pre-existing (environment-gated
tests such as the live-backend signature tests); Phase 4 introduces **zero**
skips.

## 14. Performance

Measured on the demo host (real corpus, single invocation):

| Operation | Time |
| --- | --- |
| `run_scan` of `test2` source corpus (37 components) | 0.28 s |
| IaC scan of `mixed` fixture directory | 2.3 ms |
| Full retrieval, avg over 14 canonical Q&A questions | 1.8 ms |
| Full retrieval, avg over IaC exposure questions | 0.4 ms |

Impression: exposure classification is effectively free; the Q&A retriever is
fully deterministic in‑memory retrieval with no LLM latency in the grounding
path (Ollama inference is an on-demand user step, never part of the scan).

## 15. UI validation

- `npm run build` (`tsc -b && vite build`) — **clean build**.
- `RepositoryView`: folder header shows exposure summary + badge per subtree
  (`subtreeExposure`/`exposureCounts` helpers); each finding card carries an
  `ExposureBadge`.
- `FileCodeView`: selected finding cluster shows `ExposureBadge`; the hover
  tooltip adds an `Exposure: <badge>` line; the detail panel renders the
  "Deployment Exposure" block with workload / service / ingress / namespace,
  correlation strength, the full evidence chain, and the "never an LLM
  verdict" framing.
- `DetailPanel`: new "Deployment Topology Exposure" section (badge + fields).
- `ReportView`: Section 6.5 "Deployment Topology Exposure" after Blast Radius —
  four state count cards, namespace exposure table, workload evidence-chain
  table, and the determinism note; also rendered as print page 8
  (`reportPdf.ts` PAGE_COUNT 8).
- New loadable fixture `demo_iac_exposure.cbom.json` shows a real MIXED
  finding with its evidence chain in every surface above.

## 16. Manual Q&A demo — 14 canonical questions + Phase 4 extensions

Full deterministic transcript captured from `ground_question` (the exact
service entry point). Legibility: `[id] category  latency  question → first grounded line`.

| ID | Question | Category | Latency |
| --- | --- | --- | --- |
| Q1 | What cryptographic assets were found in this repository? | general_summary | 8.5 ms |
| Q2 | Which algorithms are broken by Shor's algorithm? | general_summary | 1.3 ms |
| Q3 | Why is the RSA key generation flagged? | finding_lookup | 1.2 ms |
| Q4 | Is the AES finding broken by Shor? | finding_lookup | 1.1 ms |
| Q5 | Which cryptographic call sites are externally reachable? | general_summary | 1.7 ms |
| Q6 | What is the migration priority order? | general_summary | 1.5 ms |
| Q7 | What would it cost to migrate everything? | total_cost | 1.4 ms |
| Q8 | Which buffers would overflow after PQC migration? | finding_lookup | 1.5 ms |
| Q9 | Is the RSA in this container externally exposed? | finding_lookup | 2.1 ms |
| Q10 | Which externally exposed crypto should I migrate first? | migration_order | 1.3 ms |
| Q11 | Is any deployed TLS configuration contradicting source code? | general_summary | 1.5 ms |
| Q12 | What sensitive data is protected by vulnerable crypto? | general_summary | 1.4 ms |
| Q13 | Compare RSA, ECDSA and Ed25519. | comparison | 1.1 ms |
| Q14 | Which externally exposed vulnerable crypto should I fix first and what could break? | migration_order | 1.2 ms |

Phase 4 extension (IaC-enriched corpora):

- **I1** "Which deployments in this repo are externally exposed?" (LoadBalancer corpus) →
  `Externally Exposed Findings (3 operations)` with per-finding Workload /
  Service / Namespace + evidence chain.
- **I2** "Is the RSA in this deployment externally exposed?" → the RSA entry in
  the external inventory, chain intact.
- **M1** "Which findings have mixed exposure?" (mixed corpus) →
  `Mixed Exposure Findings (2 operations — both internal and external paths)`
  including the Ingress hop.
- **M2** "Which findings in this deployment are externally exposed?" (mixed
  corpus) → `(No findings matching this exposure state)` — honest: MIXED is
  not EXTERNAL.
- **C1** container-only Q9 guard → UNKNOWN with the "does NOT prove external
  network exposure" line.

## 17. Cross-scan isolation

Unchanged and re-verified. Every index and every conversation is scoped to a
single scan ID/serial:

- `tests/unit/test_qa_registry.py` — unknown scan IDs return `None` (never
  another scan); same conversation ID under different scans stays isolated.
- `tests/unit/test_qa_retrieval_deterministic.py::test_strict_scan_isolation`.
- `tests/unit/test_qa_cross_pillar.py::test_cross_scan_isolation_in_cross_pillar_reasoning`.

Phase 4 adds the `IAC_EXPOSURE` handler to this same pattern: the evidence
package is keyed `{scan_id, target}` and all exposure inventory is derived
from one index only.

## 18. Q&A grounding & Ollama passthrough

`IAC_EXPOSURE` intents flow: `QueryAnalyzer` → `Retriever._handle_iac_exposure`
→ `EvidencePackage` → `serialize_evidence_package` → Ollama prompt. The
serialized prompt now includes the aggregation line

```
Deployment Topology Exposure: external — N findings (X% of operations)
```

and, per finding card, `Deployment Exposure`, `Workload`, `Service`, `Ingress`,
`Namespace`, `Topology Evidence Chain`. Grounding rules are unchanged:
answers cite the evidence chain and never fabricate exposure (
`test_iac_qa.py::TestEvidencePackageSerialization` asserts the fields reach
the Ollama blob).

## 19. Honest limitations

- **Static-only.** The classifier inspects committed manifests. Live drift
  between manifest and cluster is not observed; a misconfigured live
  `samePort`/firewall reality is out of scope.
- **Label-selector semantics** are emulated: a Service whose selector cannot
  be matched to a Workload is treated as a non-join (no heuristic guesses).
- **Terraform is evidence-only.** TF resources enrich an already-correlated
  workload; they never create one.
- **No implicit `latest`** and no fuzzy digest matching — an unmatched or
  conflicting image reference yields `UNKNOWN`, by design.
- **`workload_exposures` and inventory order** are deterministic (sorted
  identities), but the classification itself reflects only what topology was
  committed to the scanned repo.
- **Reachability and exposure are separate dimensions.** `UNKNOWN` exposure is
  not "safe" — it means "not proven external; must not be assumed internal".

## 20. Next steps / out of scope

- Runtime drift checks (live cluster reconciliation) — Phase 5+ candidate.
- TLS config vs. live listener contradiction validation against real ALBs.
- Exposing `correlation_strength` in the PDF narrative (currently on-screen
  and in the CSV/JSON paths).
- Publishing `docs/COVERAGE.md` IaC inventory audit (Kubernetes workload kinds
  parsed: Deployment / StatefulSet / DaemonSet; more callers welcome).