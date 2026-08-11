# SBOM Risk Evidence Assistant — canonical specification

Status: IMPLEMENTED (live Dify app; fixture matrix green)  
Project version: `0.1.0`  
Runtime baseline: Dify 1.16.1 (api / worker / sandbox / ssrf-proxy containers)  
Rule version: `risk-rules/1.0.0`

Execution baseline: the tool runs **inside the active Dify deployment** as a
Workflow app with sandboxed code nodes, Dify HTTP nodes, and the official OSV
public API. No new container, no companion service, no host dependency.

## Product boundary

This repository is a standalone project. It does not patch or vendor the Dify
upstream source tree and it does not read Dify, model, or API credentials.
The deterministic rules are the source of truth; they are embedded in sandboxed
code nodes, and the Dify Workflow is the executable surface. Uploaded text is
always data, never an instruction. There is no arbitrary-URL ingestion and no
front-end secret.

The app was created under a unique name (`SBOM Risk Evidence 20260811 019fef`);
existing apps, bind mounts, and credentials were not modified. One standard
deployment-level change was made and documented: the SSRF proxy ACL gained
`api.osv.dev` (one line in `docker/ssrf_proxy/squid.conf.template`), required
for Dify HTTP nodes to reach the official OSV endpoint.

Supported SBOM inputs are JSON-serialized CycloneDX 1.6 and SPDX 2.3. XML,
SPDX tag/value, remote URLs, archives, and VEX interpretation are explicitly out
of scope for version 0.1.0.

## Acceptance contract (verified against the live app)

1. **Preflight**: parse and bound (2 MiB / 1,000 components); stable error codes
   (`SBOM_INVALID`, `SBOM_UNSUPPORTED`, `INPUT_TOO_LARGE`, `TOO_MANY_COMPONENTS`)
   without logging raw fields. Verified: `missing-required-field` → `failed`.
2. **Normalization**: name, version, ecosystem, PURL. Version conflict is a
   conflict, not an implicit choice; unrecognized ecosystems are `unknown` and
   never queried under a guessed type. Verified: `version-conflict` and
   `unknown-ecosystem` fixtures → component `unknown`, run `partial`.
3. **OSV query**: `v1/querybatch` with versionless PURL + explicit version
   (OSV contract); Dify HTTP node with bounded retries; `fail-branch` produces
   an explicit failed manifest with no safety claim.
4. **KEV cross-reference**: the three pinned KEV CVEs are reverse-resolved via
   OSV `v1/vulns/{id}` (bounded: exactly three lookups) to build an ID→CVE
   mapping; resolution failures only downgrade conclusions. Verified:
   `log4j-core 2.14.1` → `known_exploited` (Log4Shell via
   GHSA-jfh8-c2jp-5v3q = CVE-2021-44228).
5. **Risk rules** (`risk-rules/1.0.0`):
   - `known_exploited`: OSV vuln ID matches a KEV-resolved ID.
   - `vulnerable_evidence_incomplete`: vulnerabilities exist but no verified
     KEV evidence (snapshot date shown).
   - `no_match`: completed query, no vulnerability; copy states this is not
     proof of safety.
   - `unknown`: not queryable (conflict / unknown ecosystem / source failure).
6. **Evidence cards**: component, state, reason, query time, KEV snapshot,
   KEV SHA-256, rule version, sources, vulnerability IDs, disclaimer.
7. **Exports**: versioned JSON (`evidence-export/1.0.0`) and spreadsheet-safe
   CSV (`export-contract/1.0.0`); cells starting with `=`, `+`, `-`, `@` are
   neutralized; prompt/HTML-like fields are data only. Verified by the
   `malicious-fields` fixture.
8. **Manifest**: `run-manifest/1.0.0` with input format, timestamps, rule
   version, OSV endpoint, state (`completed`/`partial`/`failed`), summary
   counts, and unverified capabilities.
9. **End-to-end evidence**: live runs on the real Dify deployment with the
   fixture matrix, editor screenshots under `artifacts/dify/`, and the
   deterministic evidence cards / exports / manifests reproduced offline by the
   regression suite (`tools/regression_suite.py`, CI-gated).

## Failure contract (as implemented in the app)

| Condition | Stable code | Run consequence |
| --- | --- | --- |
| invalid JSON/schema/missing required field | `SBOM_INVALID` / `SBOM_UNSUPPORTED` | manifest `failed`, no claims |
| input/component limit exceeded | `INPUT_TOO_LARGE` / `TOO_MANY_COMPONENTS` | manifest `failed`, no claims |
| component/PURL version conflict | `VERSION_CONFLICT` | component `unknown`, manifest `partial` |
| unknown ecosystem | `ECOSYSTEM_UNKNOWN` | component `unknown`, manifest `partial` |
| OSV HTTP failure (retries exhausted) | `OSV_UNAVAILABLE` | manifest `failed`, no claims |
| OSV protocol error | `OSV_PROTOCOL_ERROR` | no cards, manifest `failed` |
| KEV resolution failure (per CVE) | degraded mapping | affected conclusions downgraded to `vulnerable_evidence_incomplete` |

## Evidence levels

- `CURRENT`: directly inspected current external/runtime state.
- `IMPLEMENTED`: present in this repository and verified locally / on the live app.
- `NOT_IMPLEMENTED`: absent or intentionally deferred.
- `PRODUCT_DECISION`: requires an owner decision before implementation.

| Area | Level | Evidence |
| --- | --- | --- |
| Live Dify app (unique name), workflow graph, editor screenshots | IMPLEMENTED | `artifacts/dify/` (screenshots); live runs recorded externally |
| Fixture matrix incl. abnormal cases on the live app | IMPLEMENTED | editor screenshots; deterministic cards/manifests reproduced by `tools/regression_suite.py` |
| OSV live interoperability | VERIFIED | live runs over official API through Dify HTTP node |
| LLM explanation layer | NOT_IMPLEMENTED (by design; deterministic rules never depend on a model) | manifest `unverified_capabilities` |
