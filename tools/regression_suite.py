#!/usr/bin/env python3
"""Offline regression suite for the SBOM Risk Evidence Dify workflow.

The executable surface of the workflow is a set of sandboxed Python code
nodes; their source is embedded in tools/build_native_graph.py. This suite
extracts those snippets, executes the exact same code against the committed
fixtures, and asserts the deterministic contract:

- fixture gold matrix (state per component, manifest state per run)
- offline OSV v1/querybatch transcript (fixtures-driven, no network)
- bounded KEV reverse resolution (exactly 3 lookups, stub transport)
- evidence exports validate against schemas/output/evidence-export-1.0.0.schema.json
- KEV subset SHA-256 chain: data file == data/kev/manifest.json == embedded constant
- DSL determinism: regenerating the graph yields byte-identical committed files
- graph integrity: unique node ids, resolvable selectors, fail-branch wiring
- spreadsheet safety: no CSV cell starts with = + - @

Usage: python3 tools/regression_suite.py [--verbose]
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
TOOLS_DIR = REPO_ROOT / "tools"
FIXTURES_DIR = REPO_ROOT / "fixtures" / "sbom"
KEV_FILE = REPO_ROOT / "data" / "kev" / "known_exploited_vulnerabilities_subset_2026-08-10.json"
KEV_MANIFEST = REPO_ROOT / "data" / "kev" / "manifest.json"
EXPORT_SCHEMA = REPO_ROOT / "schemas" / "output" / "evidence-export-1.0.0.schema.json"
DSL_YML = REPO_ROOT / "dify" / "sbom-risk-evidence-workflow-native.yml"
GRAPH_JSON = REPO_ROOT / "dify" / "graph-native.json"

VERBOSE = "--verbose" in sys.argv
_failures: list[str] = []
_checks = 0


def check(condition: bool, label: str, detail: str = "") -> None:
    global _checks
    _checks += 1
    status = "PASS" if condition else "FAIL"
    print(f"[{status}] {label}{(' — ' + detail) if detail else ''}")
    if not condition:
        _failures.append(label)
    if VERBOSE:
        print(f"       {condition}")


def load_build_module():
    spec = importlib.util.spec_from_file_location("build_native_graph", TOOLS_DIR / "build_native_graph.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def exec_snippet(code: str):
    namespace = {}
    exec(compile(code, "<workflow-code-node>", "exec"), namespace)
    return namespace


# ---------------------------------------------------------------------------
# Offline transports (never touch the network)
# ---------------------------------------------------------------------------

class FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    @property
    def status_code(self):
        return 200

    def json(self):
        return self._payload


class FakeRequests:
    """Stand-in for the `requests` module inside the kev_rules node.

    Records every call so the suite can assert the reverse resolution stays
    bounded to the three pinned KEV CVEs.
    """

    def __init__(self, details):
        self.details = details
        self.calls = []

    def get(self, url, timeout=None):
        self.calls.append((url, timeout))
        cve = url.rsplit("/", 1)[-1]
        return FakeResponse(self.details.get(cve, {"id": "", "aliases": []}))


KEV_DETAILS = {
    "CVE-2021-44228": {"id": "GHSA-jfh8-c2jp-5v3q", "aliases": ["CVE-2021-44228"]},
    "CVE-2021-41773": {"id": "CVE-2021-41773", "aliases": []},
    "CVE-2023-4863": {"id": "CVE-2023-4863", "aliases": []},
}

VULNS_BY_PURL = {
    ("pkg:maven/org.apache.logging.log4j/log4j-core", "2.14.1"): [
        {
            "id": "GHSA-jfh8-c2jp-5v3q",
            "aliases": ["CVE-2021-44228"],
            "summary": "Log4Shell: JNDI remote code execution in Apache Log4j 2.",
            "modified": "2022-01-07T00:00:00Z",
        }
    ],
    ("pkg:pypi/django", "2.2.0"): [
        {
            "id": "CVE-2019-11358",
            "aliases": [],
            "summary": "Django SQL injection possibility in QuerySet.order_by().",
            "modified": "2019-06-03T00:00:00Z",
        }
    ],
    ("pkg:npm/lodash", "4.17.20"): [
        {
            "id": "CVE-2021-23337",
            "aliases": [],
            "summary": "Command injection in lodash template function.",
            "modified": "2021-02-15T00:00:00Z",
        }
    ],
}


def mock_querybatch(querybatch_json: str) -> str:
    payload = json.loads(querybatch_json)
    results = []
    for query in payload.get("queries", []):
        purl = query.get("package", {}).get("purl", "")
        version = query.get("version", "")
        results.append({"vulns": VULNS_BY_PURL.get((purl, version), [])})
    return json.dumps({"results": results})


# ---------------------------------------------------------------------------
# Pipeline runner
# ---------------------------------------------------------------------------

class Nodes:
    def __init__(self, builder):
        self.preflight = exec_snippet(builder.PREFLIGHT_CODE)
        self.query = exec_snippet(builder.BUILD_QUERY_CODE)
        self.parse = exec_snippet(builder.PARSE_OSV_CODE)
        self.kev = exec_snippet(builder.KEV_RULES_CODE)
        self.export = exec_snippet(builder.EXPORT_CODE)
        self.failure = exec_snippet(builder.FAILURE_CODE)


def run_pipeline(nodes: Nodes, sbom_text: str, kev_requests) -> dict:
    """Mirror the Dify graph data flow: preflight -> query -> http -> parse -> kev -> export."""
    preflight = nodes.preflight["main"](sbom_text=sbom_text)
    if not preflight["valid"]:
        return nodes.export["main"](
            cards_json="[]",
            risk_summary_json="{}",
            doc_format=preflight["doc_format"],
            processed_at=preflight["processed_at"],
            valid=False,
            error_code=preflight["error_code"],
        )
    query = nodes.query["main"](components_json=preflight["components_json"])
    response_body = mock_querybatch(query["querybatch_json"])
    parsed = nodes.parse["main"](
        response_body=response_body,
        skipped_json=query["skipped_json"],
        queryable_count=query["queryable_count"],
    )
    cards = nodes.kev["main"](
        components_json=parsed["components_json"],
        osv_queried_at=parsed["osv_queried_at"],
        skipped_json=query["skipped_json"],
    )
    return nodes.export["main"](
        cards_json=cards["cards_json"],
        risk_summary_json=cards["risk_summary_json"],
        doc_format=preflight["doc_format"],
        processed_at=preflight["processed_at"],
        valid=True,
    )


def card_states(export_result: dict) -> list:
    evidence = json.loads(export_result["evidence_json"])
    return [card["state"] for card in evidence.get("evidence", [])]


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

def check_fixture_matrix(nodes: Nodes, kev_requests) -> None:
    fixtures = sorted(p.name for p in FIXTURES_DIR.glob("*.json") if p.name != "oversize-fixture.json")
    for name in fixtures:
        payload = (FIXTURES_DIR / name).read_text(encoding="utf-8")
        result = run_pipeline(nodes, payload, kev_requests)
        states = card_states(result)
        detail = f"state={result['status']} cards={len(states)} {states}"
        check(isinstance(result["status"], str) and result["status"] in ("completed", "partial", "failed"), f"fixture {name}: run state", detail)

    # cyclonedx-valid: log4j-core -> known_exploited; django -> vulnerable_evidence_incomplete; left-pad -> no_match
    payload = (FIXTURES_DIR / "cyclonedx-valid.json").read_text(encoding="utf-8")
    result = run_pipeline(nodes, payload, kev_requests)
    manifest = json.loads(result["run_manifest_json"])
    cards = json.loads(result["evidence_json"])["evidence"]
    check(manifest["state"] == "completed", "cyclonedx-valid: manifest completed", manifest["state"])
    check([c["state"] for c in cards] == ["known_exploited", "vulnerable_evidence_incomplete", "no_match"], "cyclonedx-valid: per-component states")
    check(manifest["summary"] == {"cards": 3, "known_exploited": 1, "vulnerable_evidence_incomplete": 1, "no_match": 1, "unknown": 0}, "cyclonedx-valid: summary counts", json.dumps(manifest["summary"]))
    ke_card = cards[0]
    check(ke_card["reason"] is None, "cyclonedx-valid: known_exploited card has null reason")
    check(ke_card["vulnerabilities"][0]["id"] == "GHSA-jfh8-c2jp-5v3q", "cyclonedx-valid: Log4Shell id", ke_card["vulnerabilities"][0]["id"])

    # cyclonedx-live-smoke: single log4j-core component -> known_exploited
    payload = (FIXTURES_DIR / "cyclonedx-live-smoke.json").read_text(encoding="utf-8")
    result = run_pipeline(nodes, payload, kev_requests)
    check(card_states(result) == ["known_exploited"], "cyclonedx-live-smoke: known_exploited")

    # spdx-valid: lodash 4.17.20 (CVE-2021-23337) -> vulnerable_evidence_incomplete; left-pad -> no_match
    payload = (FIXTURES_DIR / "spdx-valid.json").read_text(encoding="utf-8")
    result = run_pipeline(nodes, payload, kev_requests)
    cards = json.loads(result["evidence_json"])["evidence"]
    check([c["state"] for c in cards] == ["vulnerable_evidence_incomplete", "no_match"], "spdx-valid: per-component states")
    check(cards[0]["vulnerabilities"][0]["id"] == "CVE-2021-23337", "spdx-valid: lodash vulnerability id", cards[0]["vulnerabilities"][0]["id"])

    # nested-components: parent + child flattened to two cards
    payload = (FIXTURES_DIR / "nested-components.json").read_text(encoding="utf-8")
    result = run_pipeline(nodes, payload, kev_requests)
    check(card_states(result) == ["no_match", "no_match"], "nested-components: flattened to two cards")

    # unknown-ecosystem: pkg:generic is not queryable -> unknown card, partial manifest
    payload = (FIXTURES_DIR / "unknown-ecosystem.json").read_text(encoding="utf-8")
    result = run_pipeline(nodes, payload, kev_requests)
    manifest = json.loads(result["run_manifest_json"])
    check(card_states(result) == ["unknown"], "unknown-ecosystem: unknown card")
    check(manifest["state"] == "partial", "unknown-ecosystem: partial manifest")

    # version-conflict: purl 1.3.0 vs declared 2.0.0 -> unknown card, partial manifest
    payload = (FIXTURES_DIR / "version-conflict.json").read_text(encoding="utf-8")
    result = run_pipeline(nodes, payload, kev_requests)
    manifest = json.loads(result["run_manifest_json"])
    check(card_states(result) == ["unknown"], "version-conflict: unknown card")
    check(manifest["state"] == "partial", "version-conflict: partial manifest")

    # missing-required-field: preflight fails deterministically, no claims
    payload = (FIXTURES_DIR / "missing-required-field.json").read_text(encoding="utf-8")
    result = run_pipeline(nodes, payload, kev_requests)
    manifest = json.loads(result["run_manifest_json"])
    evidence = json.loads(result["evidence_json"])
    check(result["status"] == "failed", "missing-required-field: failed run")
    check(manifest["error"]["code"] == "SBOM_INVALID", "missing-required-field: stable error code", manifest["error"]["code"])
    check(evidence["evidence"] == [] and evidence["error"]["code"] == "SBOM_INVALID", "missing-required-field: no cards, error recorded")

    # malicious-fields: uploaded data never leaks into outputs; CSV is formula-safe
    payload = (FIXTURES_DIR / "malicious-fields.json").read_text(encoding="utf-8")
    result = run_pipeline(nodes, payload, kev_requests)
    evidence_text = result["evidence_json"]
    check(card_states(result) == ["no_match"], "malicious-fields: single no_match card")
    check("evil.invalid" not in evidence_text and "<script>" not in evidence_text and "169.254.169.254" not in evidence_text, "malicious-fields: no raw field echo in evidence")
    for cell in result["evidence_csv"].replace("\n", ",").split(","):
        check(not cell.startswith(("=", "+", "-", "@")), "malicious-fields: no formula-prefixed CSV cell", cell[:40])

    # oversize input: generated payload over 2 MiB -> INPUT_TOO_LARGE, failed, no claims
    big = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "components": [{"type": "library", "name": "x", "version": "1.0.0", "purl": "pkg:npm/x@1.0.0"}],
        "metadata": {"properties": [{"name": "padding", "value": "a" * (2 * 1024 * 1024)}]},
    }
    result = run_pipeline(nodes, json.dumps(big), kev_requests)
    manifest = json.loads(result["run_manifest_json"])
    check(result["status"] == "failed" and manifest["error"]["code"] == "INPUT_TOO_LARGE", "oversize: INPUT_TOO_LARGE", manifest["error"]["code"])


def check_kev_pin_chain(nodes: Nodes) -> None:
    actual = hashlib.sha256(KEV_FILE.read_bytes()).hexdigest()
    manifest = json.loads(KEV_MANIFEST.read_text(encoding="utf-8"))
    check(manifest["subset"]["sha256"] == actual, "KEV sha chain: data file == manifest.json", actual)
    check(actual == nodes.kev["KEV_SHA256"], "KEV sha chain: data file == embedded constant", actual)
    check(manifest["subset"]["cve_ids"] == list(nodes.kev["KEV_SUBSET"].keys()), "KEV sha chain: pinned CVE set matches manifest")


def check_kev_resolution_bounded(nodes: Nodes, kev_requests) -> None:
    kev_requests.calls.clear()
    payload = (FIXTURES_DIR / "cyclonedx-live-smoke.json").read_text(encoding="utf-8")
    run_pipeline(nodes, payload, kev_requests)
    check(len(kev_requests.calls) == 3, "KEV reverse resolution: exactly 3 lookups per run", str(len(kev_requests.calls)))
    check(all(url.startswith("https://api.osv.dev/v1/vulns/CVE-") for url, _t in kev_requests.calls), "KEV reverse resolution: OSV detail endpoints only")
    check(all(timeout == 8 for _url, timeout in kev_requests.calls), "KEV reverse resolution: bounded timeout")


def check_exports_validate(nodes: Nodes, kev_requests) -> None:
    import jsonschema  # noqa: PLC0415 (optional runtime dependency)

    schema = json.loads(EXPORT_SCHEMA.read_text(encoding="utf-8"))
    for name in ("cyclonedx-valid.json", "spdx-valid.json", "malicious-fields.json", "unknown-ecosystem.json"):
        payload = (FIXTURES_DIR / name).read_text(encoding="utf-8")
        result = run_pipeline(nodes, payload, kev_requests)
        jsonschema.validate(json.loads(result["evidence_json"]), schema)
        check(True, f"schema: {name} evidence validates")
    payload = (FIXTURES_DIR / "missing-required-field.json").read_text(encoding="utf-8")
    failed = run_pipeline(nodes, payload, kev_requests)
    jsonschema.validate(json.loads(failed["evidence_json"]), schema)
    check(True, "schema: failed-run evidence validates")
    failed_end = nodes.failure["main"](error_type="ECONNREFUSED")
    jsonschema.validate(json.loads(failed_end["evidence_json"]), schema)
    check(True, "schema: http fail-branch evidence validates")


def check_dsl_determinism(builder) -> None:
    import yaml  # noqa: PLC0415 (optional runtime dependency)

    dsl = builder.build_dsl()
    graph = builder.build_graph()
    regenerated_yml = yaml.safe_dump(dsl, allow_unicode=True, sort_keys=False)
    regenerated_graph = json.dumps(graph, ensure_ascii=False, indent=1)
    check(regenerated_yml == DSL_YML.read_text(encoding="utf-8"), "DSL determinism: yml byte-identical")
    check(regenerated_graph == GRAPH_JSON.read_text(encoding="utf-8"), "DSL determinism: graph byte-identical")


def check_graph_integrity(builder) -> None:
    graph = builder.build_graph()
    node_ids = [n["id"] for n in graph["nodes"]]
    check(len(node_ids) == len(set(node_ids)), "graph: node ids unique")
    check(len(graph["nodes"]) == 11 and len(graph["edges"]) == 10, "graph: 11 nodes / 10 edges")
    ids = set(node_ids)
    for edge in graph["edges"]:
        check(edge["source"] in ids and edge["target"] in ids, f"graph: edge {edge['id']} endpoints exist")
    # Built-in Dify node outputs are implicit in the graph JSON; declared code/end
    # node outputs come from the node data. start outputs its file variable.
    builtin_outputs = {
        "document-extractor": {"text"},
        "http-request": {"body", "status_code", "headers", "error_type"},
    }
    outputs_by_node = {}
    for node in graph["nodes"]:
        ntype = node["data"]["type"]
        if ntype == "start":
            outputs_by_node[node["id"]] = {v["variable"] for v in node["data"].get("variables", [])}
        elif ntype in builtin_outputs:
            outputs_by_node[node["id"]] = builtin_outputs[ntype]
        else:
            outputs = node["data"].get("outputs")
            if isinstance(outputs, dict):
                outputs_by_node[node["id"]] = set(outputs.keys())
            elif isinstance(outputs, list):
                outputs_by_node[node["id"]] = {o["variable"] for o in outputs}
    for node in graph["nodes"]:
        for var in node["data"].get("variables", []):
            selector = var.get("value_selector")
            if selector:
                src, out = selector[0], selector[1]
                check(src in outputs_by_node and out in outputs_by_node[src], f"graph: {node['id']} selector {src}.{out} resolves")
    fail_edge = any(e.get("sourceHandle") == "fail-branch" for e in graph["edges"])
    check(fail_edge, "graph: http fail-branch edge wired")
    end_nodes = [n for n in graph["nodes"] if n["data"]["type"] == "end"]
    check(len(end_nodes) == 2, "graph: success + failure end nodes", str(len(end_nodes)))


def check_fixture_files() -> None:
    for name in sorted(p.name for p in FIXTURES_DIR.glob("*.json")):
        if name == "oversize-fixture.json":
            meta = json.loads((FIXTURES_DIR / name).read_text(encoding="utf-8"))
            check(meta.get("fixture_type") == "generated", f"fixture {name}: generated pointer")
            continue
        json.loads((FIXTURES_DIR / name).read_text(encoding="utf-8"))
        check(True, f"fixture {name}: valid JSON")
    manifest = json.loads(KEV_MANIFEST.read_text(encoding="utf-8"))
    listed = [entry["path"] for entry in manifest["sources"].values() if entry.get("path")]
    for path in listed:
        check((REPO_ROOT / path).exists(), f"manifest source path exists: {path}")


def main() -> int:
    print(f"SBOM Risk Evidence — offline regression suite\nrepo: {REPO_ROOT}\n")
    builder = load_build_module()
    kev_requests = FakeRequests(KEV_DETAILS)
    sys.modules["requests"] = kev_requests
    nodes = Nodes(builder)

    check_fixture_files()
    check_fixture_matrix(nodes, kev_requests)
    check_kev_pin_chain(nodes)
    check_kev_resolution_bounded(nodes, kev_requests)
    check_exports_validate(nodes, kev_requests)
    check_dsl_determinism(builder)
    check_graph_integrity(builder)

    print(f"\n{_checks - len(_failures)}/{_checks} checks passed")
    if _failures:
        print("FAILED checks:")
        for label in _failures:
            print(f"  - {label}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
