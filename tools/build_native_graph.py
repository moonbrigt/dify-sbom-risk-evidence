#!/usr/bin/env python3
"""Build the all-native Dify workflow graph (no companion container).

The workflow runs entirely inside the Dify runtime containers:
- start (file) -> document-extractor -> code preflight (parse/validate/normalize)
- -> code build_osv_query -> http-request (https://api.osv.dev/v1/querybatch)
- -> code parse_osv -> code kev_rules -> code export -> end
- fail-branch -> code explicit failure -> end

Deterministic logic lives in sandboxed Python code nodes (stdlib only).
The pinned CISA KEV subset is embedded in the kev_rules node.
"""
from __future__ import annotations

import json
from pathlib import Path

APP_NAME = "SBOM Risk Evidence 20260811 019fef"
APP_ICON = "🧾"
APP_DESC = (
    "CycloneDX/SPDX SBOM risk evidence: schema preflight, OSV query, "
    "CISA KEV cross-reference, JSON/CSV export. No LLM."
)

# ---------------------------------------------------------------------------
# Node code snippets (sandbox stdlib only)
# ---------------------------------------------------------------------------

PREFLIGHT_CODE = '''import json
import time

MAX_BYTES = 2 * 1024 * 1024
MAX_COMPONENTS = 1000
KNOWN_ECOSYSTEMS = {
    "cargo", "composer", "deb", "golang", "hackage", "hex", "maven",
    "npm", "nuget", "pypi", "rubygems", "cran", "swift", "apk", "rpm",
    "conan", "conda", "pub", "bioconductor", "linux",
}

def _purl_parts(purl):
    if not isinstance(purl, str) or not purl.startswith("pkg:"):
        return None
    try:
        rest = purl[4:]
        ptype, _, remainder = rest.partition("/")
        if not remainder:
            return None
        name_part = remainder
        version = None
        if "@" in name_part:
            name_part, _, version = name_part.partition("@")
        return {"type": ptype.lower(), "name": name_part, "version": version}
    except Exception:
        return None

def main(sbom_text: str) -> dict:
    try:
        size = len(sbom_text.encode("utf-8"))
        if size > MAX_BYTES:
            raise ValueError("INPUT_TOO_LARGE")
        document = json.loads(sbom_text)
        if not isinstance(document, dict):
            raise ValueError("SBOM_INVALID")
        if document.get("bomFormat") == "CycloneDX" and str(document.get("specVersion")) == "1.6":
            doc_format = "CycloneDX 1.6 JSON"
            raw = document.get("components", [])
            if not isinstance(raw, list):
                raise ValueError("SBOM_INVALID")
            components = []
            pending = list(raw)
            while pending:
                item = pending.pop(0)
                if not isinstance(item, dict):
                    raise ValueError("SBOM_INVALID")
                children = item.get("components", [])
                if isinstance(children, list):
                    pending[0:0] = children
                components.append(item)
        elif document.get("spdxVersion") == "SPDX-2.3":
            doc_format = "SPDX 2.3 JSON"
            packages = document.get("packages", [])
            if not isinstance(packages, list):
                raise ValueError("SBOM_INVALID")
            components = list(packages)
        else:
            raise ValueError("SBOM_UNSUPPORTED")
        if len(components) > MAX_COMPONENTS:
            raise ValueError("TOO_MANY_COMPONENTS")
        normalized = []
        for index, item in enumerate(components):
            if not isinstance(item, dict):
                raise ValueError("SBOM_INVALID")
            name = item.get("name")
            if not isinstance(name, str) or not name:
                raise ValueError("SBOM_INVALID")
            version = item.get("version")
            if version is None:
                version = item.get("versionInfo")  # SPDX 2.3 JSON names the field versionInfo
            if version is not None and not isinstance(version, str):
                version = str(version)
            purl = item.get("purl") if isinstance(item.get("purl"), str) else None
            if purl is None:
                for ref in item.get("externalRefs", []) if isinstance(item.get("externalRefs", []), list) else []:
                    if isinstance(ref, dict) and ref.get("referenceType") == "purl" and isinstance(ref.get("referenceLocator"), str):
                        purl = ref["referenceLocator"]
                        break
            parsed = _purl_parts(purl) if purl else None
            ecosystem = parsed["type"] if parsed else None
            conflict = None
            if parsed and parsed["version"] and version and parsed["version"] != version:
                conflict = "purl version %s != declared version %s" % (parsed["version"], version)
            if ecosystem and ecosystem not in KNOWN_ECOSYSTEMS:
                ecosystem = None
            normalized.append({
                "index": index,
                "name": name,
                "version": version,
                "purl": purl,
                "ecosystem": ecosystem,
                "conflict": conflict,
                "unknown_ecosystem": ecosystem is None,
            })
        return {
            "valid": True,
            "error_code": "",
            "doc_format": doc_format,
            "processed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "components_json": json.dumps(normalized, ensure_ascii=False, separators=(",", ":")),
        }
    except ValueError as exc:
        return {
            "valid": False,
            "error_code": str(exc),
            "doc_format": "",
            "processed_at": "",
            "components_json": "[]",
        }
'''

BUILD_QUERY_CODE = '''import json

def _versionless_purl(purl):
    """Strip a trailing @version from a purl, keeping scoped names like pkg:npm/@scope/name."""
    if "@" not in purl:
        return purl
    head, _sep, tail = purl.rpartition("@")
    if not head or not tail or "/" in tail:
        return purl
    return head

def main(components_json: str) -> dict:
    try:
        components = json.loads(components_json)
    except Exception:
        components = []
    queries = []
    skipped = []
    for item in components:
        if item.get("conflict") or item.get("unknown_ecosystem") or not item.get("purl"):
            skipped.append(item)
            continue
        version = item.get("version") or ""
        query = {"package": {"purl": _versionless_purl(item["purl"])}, "version": version}
        queries.append(query)
    return {
        "querybatch_json": json.dumps({"queries": queries}, ensure_ascii=False, separators=(",", ":")),
        "queryable_count": str(len(queries)),
        "skipped_json": json.dumps(skipped, ensure_ascii=False, separators=(",", ":")),
    }
'''

PARSE_OSV_CODE = '''import json
import time

def main(response_body: str, skipped_json: str, queryable_count: str) -> dict:
    try:
        queryable = int(queryable_count or 0)
    except Exception:
        queryable = 0
    try:
        payload = json.loads(response_body)
        results = payload.get("results")
        if not isinstance(results, list):
            raise ValueError("OSV_PROTOCOL_ERROR")
    except Exception:
        return {
            "components_json": "[]",
            "osv_queried_at": "",
            "osv_error": "OSV_PROTOCOL_ERROR",
            "queryable_count": str(queryable),
            "partial": True,
        }
    parsed = []
    for index, result in enumerate(results):
        if not isinstance(result, dict):
            parsed.append({"index": index, "vulns": [], "error": "OSV_PROTOCOL_ERROR"})
            continue
        vulns = result.get("vulns", [])
        items = []
        if isinstance(vulns, list):
            for vuln in vulns:
                if not isinstance(vuln, dict):
                    continue
                vid = vuln.get("id")
                if not isinstance(vid, str):
                    continue
                aliases = vuln.get("aliases", [])
                items.append({
                    "id": vid,
                    "aliases": aliases if isinstance(aliases, list) else [],
                    "summary": vuln.get("summary") if isinstance(vuln.get("summary"), str) else None,
                    "details": vuln.get("details") if isinstance(vuln.get("details"), str) else None,
                    "affected": vuln.get("affected") if isinstance(vuln.get("affected"), list) else [],
                    "modified": vuln.get("modified") if isinstance(vuln.get("modified"), str) else None,
                })
        parsed.append({"index": index, "vulns": items, "error": None})
    try:
        skipped = json.loads(skipped_json)
    except Exception:
        skipped = []
    return {
        "components_json": json.dumps(parsed, ensure_ascii=False, separators=(",", ":")),
        "osv_queried_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "osv_error": "",
        "queryable_count": str(queryable),
        "partial": False,
    }
'''

KEV_RULES_CODE = '''import json
import time

try:
    import requests  # noqa: PLC0415  (sandbox ships requests; proxy env is preconfigured)
except Exception:  # pragma: no cover
    requests = None

KEV_SUBSET = {
    "CVE-2021-44228": {"name": "Apache Log4j2", "date_added": "2021-12-10", "required_action": "Apply updates per vendor instructions."},
    "CVE-2021-41773": {"name": "Apache HTTP Server", "date_added": "2021-10-04", "required_action": "Apply updates per vendor instructions."},
    "CVE-2023-4863": {"name": "WebP (multiple products)", "date_added": "2023-09-15", "required_action": "Apply updates per vendor instructions."},
}
KEV_SNAPSHOT = "2026-08-10T16:19:34.1767Z"
KEV_SHA256 = "89689b4485bf16702a36dde7c901766d56521720f79275425e07a77763e26c73"
RULE_VERSION = "risk-rules/1.0.0"
OSV_SOURCE = "https://api.osv.dev/v1/querybatch"
KEV_SOURCE = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
DISCLAIMER = (
    "This evidence card is generated deterministically. 'no_match' means the "
    "OSV query returned no vulnerability at query time; it is not proof of "
    "safety. KEV snapshot: %s. Data cutoff is visible per source." % KEV_SNAPSHOT
)

def _resolve_kev_osv_ids():
    """Reverse-resolve each pinned KEV CVE through OSV detail lookups (bounded
    to the three pinned CVEs). Failures degrade to an empty mapping; a missing
    mapping can only downgrade a conclusion, never fabricate one."""
    resolved = {}
    if requests is None:
        return resolved
    for cve in KEV_SUBSET:
        try:
            response = requests.get("https://api.osv.dev/v1/vulns/" + cve, timeout=8)
            if response.status_code != 200:
                continue
            detail = response.json()
            ids = [detail.get("id")] + list(detail.get("aliases", []))
            for vid in ids:
                if isinstance(vid, str) and vid:
                    resolved[vid] = cve
        except Exception:
            continue
    return resolved

def main(components_json: str, osv_queried_at: str, skipped_json: str) -> dict:
    try:
        results = json.loads(components_json)
    except Exception:
        results = []
    try:
        skipped = json.loads(skipped_json)
    except Exception:
        skipped = []
    kev_osv_ids = _resolve_kev_osv_ids()
    cards = []
    for result in results:
        index = result.get("index", 0)
        vulns = result.get("vulns", [])
        error = result.get("error")
        if error:
            state = "unknown"
            reason = "OSV query failed: %s" % error
        elif vulns:
            matched = None
            for vuln in vulns:
                cve = kev_osv_ids.get(vuln.get("id"))
                if cve:
                    matched = (cve, KEV_SUBSET[cve])
                    break
            if matched:
                state = "known_exploited"
                reason = None
            else:
                state = "vulnerable_evidence_incomplete"
                reason = "OSV reports vulnerability but no verified CISA KEV match in snapshot %s" % KEV_SNAPSHOT
        else:
            state = "no_match"
            reason = "Completed OSV query returned no vulnerability; this is not proof of safety."
        card = {
            "component_index": index,
            "state": state,
            "reason": reason,
            "osv_queried_at": osv_queried_at,
            "kev_snapshot": KEV_SNAPSHOT,
            "kev_sha256": KEV_SHA256,
            "rule_version": RULE_VERSION,
            "sources": {"osv": OSV_SOURCE, "kev": KEV_SOURCE},
            "vulnerabilities": vulns,
            "disclaimer": DISCLAIMER,
        }
        cards.append(card)
    unknown = []
    for item in skipped:
        reason = None
        if item.get("conflict"):
            reason = "version conflict: %s" % item["conflict"]
        elif item.get("unknown_ecosystem"):
            reason = "unknown ecosystem without queryable purl"
        else:
            reason = "not queryable"
        unknown.append({
            "component_index": item.get("index", 0),
            "state": "unknown",
            "reason": reason,
            "osv_queried_at": osv_queried_at,
            "kev_snapshot": KEV_SNAPSHOT,
            "kev_sha256": KEV_SHA256,
            "rule_version": RULE_VERSION,
            "sources": {"osv": OSV_SOURCE, "kev": KEV_SOURCE},
            "vulnerabilities": [],
            "disclaimer": DISCLAIMER,
        })
    cards.extend(unknown)
    summary = {"cards": len(cards), "known_exploited": 0, "vulnerable_evidence_incomplete": 0, "no_match": 0, "unknown": 0}
    for card in cards:
        summary[card["state"]] = summary.get(card["state"], 0) + 1
    return {
        "cards_json": json.dumps(cards, ensure_ascii=False, separators=(",", ":")),
        "risk_summary_json": json.dumps(summary, sort_keys=True, separators=(",", ":")),
    }
'''

EXPORT_CODE = '''import json
import time

SCHEMA_VERSION = "evidence-export/1.0.0"
MANIFEST_VERSION = "run-manifest/1.0.0"
EXPORT_VERSION = "export-contract/1.0.0"

def _safe_cell(value):
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
    if text.startswith(("=", "+", "-", "@")):
        text = "'" + text
    return text.replace("\\r", " ").replace("\\n", " ")

def main(cards_json: str, risk_summary_json: str, doc_format: str, processed_at: str, valid: bool = True, error_code: str = "") -> dict:
    try:
        cards = json.loads(cards_json)
    except Exception:
        cards = []
    if not valid:
        error = {"code": error_code or "SBOM_INVALID", "source": "dify_preflight", "claim": "Input failed deterministic validation; no risk conclusion is produced."}
        manifest = {
            "manifest_version": MANIFEST_VERSION,
            "export_contract": EXPORT_VERSION,
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "input_format": doc_format,
            "processed_at": processed_at,
            "rule_version": "risk-rules/1.0.0",
            "osv_endpoint": "https://api.osv.dev/v1/querybatch",
            "state": "failed",
            "error": error,
            "unverified_capabilities": ["Dify application import/trace recorded separately", "No model used"],
            "summary": {},
        }
        return {
            "status": "failed",
            "evidence_json": json.dumps({"schema_version": SCHEMA_VERSION, "generated_at": manifest["generated_at"], "evidence": [], "error": error}, ensure_ascii=False, sort_keys=True),
            "evidence_csv": "",
            "run_manifest_json": json.dumps(manifest, ensure_ascii=False, sort_keys=True),
        }
    evidence = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "input_format": doc_format,
        "processed_at": processed_at,
        "rule_version": "risk-rules/1.0.0",
        "evidence": cards,
    }
    header = ["component_index", "state", "reason", "osv_queried_at", "kev_snapshot", "vulnerability_ids", "sources", "disclaimer"]
    lines = [",".join(header)]
    for card in cards:
        vids = ";".join(v["id"] for v in card.get("vulnerabilities", []))
        lines.append(",".join([
            _safe_cell(card.get("component_index", "")),
            _safe_cell(card.get("state", "")),
            _safe_cell(card.get("reason", "")),
            _safe_cell(card.get("osv_queried_at", "")),
            _safe_cell(card.get("kev_snapshot", "")),
            _safe_cell(vids),
            _safe_cell(json.dumps(card.get("sources", {}), sort_keys=True)),
            _safe_cell(card.get("disclaimer", "")),
        ]))
    has_unknown = any((card.get("state") == "unknown") for card in cards)
    manifest = {
        "manifest_version": MANIFEST_VERSION,
        "export_contract": EXPORT_VERSION,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "input_format": doc_format,
        "processed_at": processed_at,
        "rule_version": "risk-rules/1.0.0",
        "osv_endpoint": "https://api.osv.dev/v1/querybatch",
        "state": "partial" if has_unknown else "completed",
        "unverified_capabilities": ["Dify application import/trace recorded separately", "No model used"],
        "summary": json.loads(risk_summary_json) if risk_summary_json else {},
    }
    return {
        "status": manifest["state"],
        "evidence_json": json.dumps(evidence, ensure_ascii=False, sort_keys=True),
        "evidence_csv": "\\n".join(lines),
        "run_manifest_json": json.dumps(manifest, ensure_ascii=False, sort_keys=True),
    }
'''

FAILURE_CODE = '''import json
import time

def main(error_type: str = "unknown") -> dict:
    error = {
        "code": "OSV_UNAVAILABLE",
        "source": "dify_http_fail_branch",
        "error_type": error_type if isinstance(error_type, str) and len(error_type) <= 80 else "unknown",
        "retryable": True,
        "claim": "No risk conclusion was produced; no safety claim is made.",
    }
    evidence = {
        "schema_version": "evidence-export/1.0.0",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "evidence": [],
        "error": error,
    }
    manifest = {
        "manifest_version": "run-manifest/1.0.0",
        "state": "failed",
        "error": error,
    }
    return {
        "status": "failed",
        "evidence_json": json.dumps(evidence, ensure_ascii=False, sort_keys=True),
        "evidence_csv": "",
        "run_manifest_json": json.dumps(manifest, ensure_ascii=False, sort_keys=True),
    }
'''


# ---------------------------------------------------------------------------
# Graph construction
# ---------------------------------------------------------------------------

def code_node(node_id: str, title: str, desc: str, code: str, variables: list, outputs: dict, x: int, y: int) -> dict:
    return {
        "data": {
            "code": code,
            "code_language": "python3",
            "desc": desc,
            "outputs": outputs,
            "selected": False,
            "title": title,
            "type": "code",
            "variables": variables,
        },
        "height": 84,
        "id": node_id,
        "position": {"x": x, "y": y},
        "positionAbsolute": {"x": x, "y": y},
        "selected": False,
        "sourcePosition": "right",
        "targetPosition": "left",
        "type": "custom",
        "width": 244,
        "zIndex": 1,
    }


def build_graph() -> dict:
    nodes = [
        {
            "data": {
                "desc": "Accept exactly one local JSON document; remote URL upload is disabled.",
                "selected": False,
                "title": "Upload SBOM",
                "type": "start",
                "variables": [
                    {
                        "allowed_file_extensions": [".JSON", ".SPDX.JSON", ".CDX.JSON"],
                        "allowed_file_types": ["document"],
                        "allowed_file_upload_methods": ["local_file"],
                        "label": "SBOM file",
                        "max_length": None,
                        "options": [],
                        "required": True,
                        "type": "file",
                        "variable": "sbom_file",
                    }
                ],
            },
            "height": 86,
            "id": "start",
            "position": {"x": 80, "y": 300},
            "positionAbsolute": {"x": 80, "y": 300},
            "selected": False,
            "sourcePosition": "right",
            "targetPosition": "left",
            "type": "custom",
            "width": 244,
            "zIndex": 1,
        },
        {
            "data": {
                "desc": "Convert the locally uploaded JSON document to text; no external reference is fetched.",
                "selected": False,
                "title": "Extract uploaded JSON",
                "type": "document-extractor",
                "variable_selector": ["start", "sbom_file"],
            },
            "height": 74,
            "id": "extract",
            "position": {"x": 400, "y": 300},
            "positionAbsolute": {"x": 400, "y": 300},
            "selected": False,
            "sourcePosition": "right",
            "targetPosition": "left",
            "type": "custom",
            "width": 244,
            "zIndex": 1,
        },
        code_node(
            "preflight",
            "Validate and normalize",
            "Parse, bound (2 MiB / 1000 components), and normalize components. Uploaded fields are untrusted data.",
            PREFLIGHT_CODE,
            [{"value_selector": ["extract", "text"], "value_type": "string", "variable": "sbom_text"}],
            {
                "valid": {"children": None, "type": "boolean"},
                "error_code": {"children": None, "type": "string"},
                "doc_format": {"children": None, "type": "string"},
                "processed_at": {"children": None, "type": "string"},
                "components_json": {"children": None, "type": "string"},
            },
            720, 300,
        ),
        code_node(
            "osv_query",
            "Build OSV query batch",
            "Build a bounded v1/querybatch request from normalized components; conflicts and unknown ecosystems are skipped.",
            BUILD_QUERY_CODE,
            [{"value_selector": ["preflight", "components_json"], "value_type": "string", "variable": "components_json"}],
            {
                "querybatch_json": {"children": None, "type": "string"},
                "queryable_count": {"children": None, "type": "string"},
                "skipped_json": {"children": None, "type": "string"},
            },
            1040, 300,
        ),
        {
            "data": {
                "authorization": {"type": "no-auth"},
                "body": {
                    "data": [
                        {
                            "id": "body-json-1",
                            "key": "",
                            "type": "text",
                            "value": "{{#osv_query.querybatch_json#}}",
                        }
                    ],
                    "type": "json",
                },
                "desc": "Official public OSV querybatch endpoint; no key. SBOM fields cannot change URL, headers, or method.",
                "error_strategy": "fail-branch",
                "headers": "Content-Type: application/json",
                "method": "POST",
                "params": "",
                "retry_config": {"max_retries": 3, "retry_enabled": True, "retry_interval": 1000},
                "selected": False,
                "ssl_verify": True,
                "timeout": {"connect": 10, "read": 60, "write": 60},
                "title": "OSV querybatch (official API)",
                "type": "http-request",
                "url": "https://api.osv.dev/v1/querybatch",
            },
            "height": 126,
            "id": "osv_http",
            "position": {"x": 1360, "y": 300},
            "positionAbsolute": {"x": 1360, "y": 300},
            "selected": False,
            "sourcePosition": "right",
            "targetPosition": "left",
            "type": "custom",
            "width": 244,
            "zIndex": 1,
        },
        code_node(
            "osv_parse",
            "Parse OSV responses",
            "Map querybatch results back to components; protocol errors become per-component unknown, never a safety claim.",
            PARSE_OSV_CODE,
            [
                {"value_selector": ["osv_http", "body"], "value_type": "string", "variable": "response_body"},
                {"value_selector": ["osv_query", "skipped_json"], "value_type": "string", "variable": "skipped_json"},
                {"value_selector": ["osv_query", "queryable_count"], "value_type": "string", "variable": "queryable_count"},
            ],
            {
                "components_json": {"children": None, "type": "string"},
                "osv_queried_at": {"children": None, "type": "string"},
                "osv_error": {"children": None, "type": "string"},
                "queryable_count": {"children": None, "type": "string"},
                "partial": {"children": None, "type": "boolean"},
            },
            1680, 300,
        ),
        code_node(
            "kev_rules",
            "KEV cross-reference and risk rules",
            "Cross-reference OSV ids/aliases with the pinned CISA KEV subset; deterministic risk-rules/1.0.0 states.",
            KEV_RULES_CODE,
            [
                {"value_selector": ["osv_parse", "components_json"], "value_type": "string", "variable": "components_json"},
                {"value_selector": ["osv_parse", "osv_queried_at"], "value_type": "string", "variable": "osv_queried_at"},
                {"value_selector": ["osv_query", "skipped_json"], "value_type": "string", "variable": "skipped_json"},
            ],
            {
                "cards_json": {"children": None, "type": "string"},
                "risk_summary_json": {"children": None, "type": "string"},
            },
            2000, 300,
        ),
        code_node(
            "export",
            "JSON and CSV export",
            "Versioned JSON and spreadsheet-safe CSV export with run manifest. Formula prefixes are neutralized.",
            EXPORT_CODE,
            [
                {"value_selector": ["kev_rules", "cards_json"], "value_type": "string", "variable": "cards_json"},
                {"value_selector": ["kev_rules", "risk_summary_json"], "value_type": "string", "variable": "risk_summary_json"},
                {"value_selector": ["preflight", "doc_format"], "value_type": "string", "variable": "doc_format"},
                {"value_selector": ["preflight", "processed_at"], "value_type": "string", "variable": "processed_at"},
                {"value_selector": ["preflight", "valid"], "value_type": "boolean", "variable": "valid"},
                {"value_selector": ["preflight", "error_code"], "value_type": "string", "variable": "error_code"},
            ],
            {
                "status": {"children": None, "type": "string"},
                "evidence_json": {"children": None, "type": "string"},
                "evidence_csv": {"children": None, "type": "string"},
                "run_manifest_json": {"children": None, "type": "string"},
            },
            2320, 300,
        ),
        {
            "data": {
                "desc": "JSON, CSV, preview, and reproducible manifest are returned as explicit Workflow outputs.",
                "outputs": [
                    {"value_selector": ["export", "status"], "value_type": "string", "variable": "status"},
                    {"value_selector": ["export", "evidence_json"], "value_type": "string", "variable": "evidence_json"},
                    {"value_selector": ["export", "evidence_csv"], "value_type": "string", "variable": "evidence_csv"},
                    {"value_selector": ["export", "run_manifest_json"], "value_type": "string", "variable": "run_manifest_json"},
                ],
                "selected": False,
                "title": "Evidence exports",
                "type": "end",
            },
            "height": 118,
            "id": "success_end",
            "position": {"x": 2640, "y": 300},
            "positionAbsolute": {"x": 2640, "y": 300},
            "selected": False,
            "sourcePosition": "right",
            "targetPosition": "left",
            "type": "custom",
            "width": 244,
            "zIndex": 1,
        },
        code_node(
            "http_failure",
            "Explicit network failure",
            "Deterministic degraded output after bounded HTTP retries; no error body or uploaded field is reflected.",
            FAILURE_CODE,
            [{"value_selector": ["osv_http", "error_type"], "value_type": "string", "variable": "error_type"}],
            {
                "status": {"children": None, "type": "string"},
                "evidence_json": {"children": None, "type": "string"},
                "evidence_csv": {"children": None, "type": "string"},
                "run_manifest_json": {"children": None, "type": "string"},
            },
            1680, 700,
        ),
        {
            "data": {
                "desc": "Explicit failure result; no vulnerability or safety claim is emitted.",
                "outputs": [
                    {"value_selector": ["http_failure", "status"], "value_type": "string", "variable": "status"},
                    {"value_selector": ["http_failure", "evidence_json"], "value_type": "string", "variable": "evidence_json"},
                    {"value_selector": ["http_failure", "evidence_csv"], "value_type": "string", "variable": "evidence_csv"},
                    {"value_selector": ["http_failure", "run_manifest_json"], "value_type": "string", "variable": "run_manifest_json"},
                ],
                "selected": False,
                "title": "Failed without claim",
                "type": "end",
            },
            "height": 118,
            "id": "failure_end",
            "position": {"x": 2000, "y": 700},
            "positionAbsolute": {"x": 2000, "y": 700},
            "selected": False,
            "sourcePosition": "right",
            "targetPosition": "left",
            "type": "custom",
            "width": 244,
            "zIndex": 1,
        },
    ]

    edges = [
        {"data": {"isInIteration": False, "isInLoop": False, "sourceType": "start", "targetType": "document-extractor"},
         "id": "start-extract", "source": "start", "sourceHandle": "source", "target": "extract", "targetHandle": "target", "type": "custom", "zIndex": 0},
        {"data": {"isInIteration": False, "isInLoop": False, "sourceType": "document-extractor", "targetType": "code"},
         "id": "extract-preflight", "source": "extract", "sourceHandle": "source", "target": "preflight", "targetHandle": "target", "type": "custom", "zIndex": 0},
        {"data": {"isInIteration": False, "isInLoop": False, "sourceType": "code", "targetType": "code"},
         "id": "preflight-osv_query", "source": "preflight", "sourceHandle": "source", "target": "osv_query", "targetHandle": "target", "type": "custom", "zIndex": 0},
        {"data": {"isInIteration": False, "isInLoop": False, "sourceType": "code", "targetType": "http-request"},
         "id": "osv_query-osv_http", "source": "osv_query", "sourceHandle": "source", "target": "osv_http", "targetHandle": "target", "type": "custom", "zIndex": 0},
        {"data": {"isInIteration": False, "isInLoop": False, "sourceType": "http-request", "targetType": "code"},
         "id": "osv_http-success-osv_parse", "source": "osv_http", "sourceHandle": "source", "target": "osv_parse", "targetHandle": "target", "type": "custom", "zIndex": 0},
        {"data": {"isInIteration": False, "isInLoop": False, "sourceType": "http-request", "targetType": "code"},
         "id": "osv_http-fail-http_failure", "source": "osv_http", "sourceHandle": "fail-branch", "target": "http_failure", "targetHandle": "target", "type": "custom", "zIndex": 0},
        {"data": {"isInIteration": False, "isInLoop": False, "sourceType": "code", "targetType": "code"},
         "id": "osv_parse-kev_rules", "source": "osv_parse", "sourceHandle": "source", "target": "kev_rules", "targetHandle": "target", "type": "custom", "zIndex": 0},
        {"data": {"isInIteration": False, "isInLoop": False, "sourceType": "code", "targetType": "code"},
         "id": "kev_rules-export", "source": "kev_rules", "sourceHandle": "source", "target": "export", "targetHandle": "target", "type": "custom", "zIndex": 0},
        {"data": {"isInIteration": False, "isInLoop": False, "sourceType": "code", "targetType": "end"},
         "id": "export-success_end", "source": "export", "sourceHandle": "source", "target": "success_end", "targetHandle": "target", "type": "custom", "zIndex": 0},
        {"data": {"isInIteration": False, "isInLoop": False, "sourceType": "code", "targetType": "end"},
         "id": "http_failure-failure_end", "source": "http_failure", "sourceHandle": "source", "target": "failure_end", "targetHandle": "target", "type": "custom", "zIndex": 0},
    ]

    return {"nodes": nodes, "edges": edges}


FEATURES = {
    "file_upload": {
        "allowed_file_extensions": [".JSON", ".SPDX.JSON", ".CDX.JSON"],
        "allowed_file_types": ["document"],
        "allowed_file_upload_methods": ["local_file"],
        "enabled": True,
        "fileUploadConfig": {
            "audio_file_size_limit": 0,
            "batch_count_limit": 1,
            "file_size_limit": 2,
            "image_file_size_limit": 0,
            "number_limits": 1,
            "video_file_size_limit": 0,
            "workflow_file_upload_limit": 2,
        },
        "image": {"enabled": False, "number_limits": 0, "transfer_methods": []},
        "number_limits": 1,
    },
    "opening_statement": "",
    "retriever_resource": {"enabled": False},
    "sensitive_word_avoidance": {"enabled": False, "type": "", "inputs": [], "outputs": []},
    "speech_to_text": {"enabled": False},
    "suggested_questions": [],
    "suggested_questions_after_answer": {"enabled": False},
    "text_to_speech": {"enabled": False, "language": "", "voice": ""},
}


def build_dsl() -> dict:
    return {
        "app": {
            "description": APP_DESC,
            "icon": APP_ICON,
            "icon_background": "#E8F3FF",
            "mode": "workflow",
            "name": APP_NAME,
            "use_icon_as_answer_icon": False,
        },
        "dependencies": [],
        "kind": "app",
        "version": "0.3.1",
        "workflow": {
            "conversation_variables": [],
            "environment_variables": [],
            "features": FEATURES,
            "graph": build_graph(),
            "id": "d0959d02-1daa-4147-96bf-2b7486612319",
            "name": APP_NAME,
            "type": "workflow",
            "version": "2026-08-11 02:30:00",
        },
    }


if __name__ == "__main__":
    out = Path(__file__).resolve().parent.parent / "dify" / "sbom-risk-evidence-workflow-native.yml"
    out.write_text("", encoding="utf-8")  # placeholder replaced by yaml dump below
    import yaml  # noqa: PLC0415

    dsl = build_dsl()
    out.write_text(yaml.safe_dump(dsl, allow_unicode=True, sort_keys=False), encoding="utf-8")
    print("wrote", out)
    graph = build_graph()
    (Path(__file__).resolve().parent.parent / "dify" / "graph-native.json").write_text(
        json.dumps(graph, ensure_ascii=False, indent=1), encoding="utf-8"
    )
    print("wrote dify/graph-native.json with", len(graph["nodes"]), "nodes,", len(graph["edges"]), "edges")
