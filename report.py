"""JSON, Markdown, and run metadata report writer."""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any


def write(findings: list[dict[str, Any]], metadata: dict[str, Any], out_dir: Path) -> None:
    # Evidence contains source text. Hide it for every finding on a credential line.
    credential_lines = {
        (finding.get("file"), finding.get("line"))
        for finding in findings
        if finding.get("cwe") == "CWE-798"
    }
    findings = [
        {**finding, "evidence": "[REDACTED]"}
        if (finding.get("file"), finding.get("line")) in credential_lines
        else finding
        for finding in findings
    ]
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "findings.json").write_text(
        json.dumps(findings, indent=2, ensure_ascii=False), encoding="utf-8")
    (out_dir / "run.json").write_text(
        json.dumps(metadata, indent=2, ensure_ascii=False), encoding="utf-8")
    rule_rows: dict[str, dict[str, Any]] = {}
    for finding in findings:
        cwe = finding.get("cwe", "CWE-?")
        rule_rows.setdefault(cwe, {
            "id": cwe,
            "shortDescription": {"text": finding.get("title", cwe)},
            "help": {"text": finding.get("recommendation", "Review this finding.")},
        })
    severity_map = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}
    sarif_results = []
    for finding in findings:
        artifact_uri = Path(finding.get("file", "unknown")).resolve().as_uri()
        sarif_results.append({
            "ruleId": finding.get("cwe", "CWE-?"),
            "level": severity_map.get(str(finding.get("severity", "medium")).lower(), "warning"),
            "message": {"text": f"{finding.get('reason', '')} Evidence: {finding.get('evidence', '')}"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": artifact_uri},
                "region": {"startLine": max(1, int(finding.get("line", 1)))},
            }}],
            "properties": {
                "confidence": finding.get("confidence", 0.0),
                "detector": finding.get("source", "unknown"),
                "recommendation": finding.get("recommendation", ""),
            },
        })
    sarif = {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {
            "name": "SecureGuard", "semanticVersion": "0.3.0",
            "rules": list(rule_rows.values()),
        }}, "results": sarif_results}],
    }
    (out_dir / "findings.sarif").write_text(json.dumps(sarif, indent=2, ensure_ascii=False), encoding="utf-8")

    counts = Counter(f.get("cwe", "CWE-?") for f in findings)
    detector_counts = Counter(f.get("source", "unknown") for f in findings)
    severity_counts = Counter(str(f.get("severity", "medium")).lower() for f in findings)
    model_metrics = metadata.get("model_metrics", {})
    rag_docs = metadata.get("rag_knowledge_base_documents", metadata.get("rag_documents", 0))
    rag_stats = metadata.get("rag_base", {})
    lines = ["# Secure Coding Audit Report", "",
             f"- Files scanned: {metadata.get('files_scanned', 0)}",
             f"- Candidate findings: {len(findings)}",
             f"- Local LLM status: {metadata.get('llm_status', 'not requested')}",
             f"- Local knowledge base: {rag_docs} normalized records, "
             f"{rag_stats.get('unique_cwes', 'unknown')} unique CWE entries",
             f"- Invalid knowledge-base rows skipped: {rag_stats.get('invalid_records', 'not recorded')}",
             f"- Exact duplicate knowledge-base rows removed: {rag_stats.get('duplicates_removed', 'not recorded')}",
             f"- RAG results returned for scanned files: {metadata.get('rag_retrievals', 'not recorded')}",
             f"- Exact CWE references attached to findings: {metadata.get('exact_cwe_references', 0)}",
             f"- Findings whose CWE was absent from the knowledge base: {metadata.get('missing_cwe_references', 0)}",
             f"- Duration: {metadata.get('elapsed_seconds', 'not recorded')} seconds", "",
             "> Findings are candidates for human review. Static patterns and LLM output do not prove exploitability.", ""]
    kb_sources = rag_stats.get("sources", [])
    if kb_sources:
        lines.insert(7, "- Knowledge-base files: " + ", ".join(f"`{name}`" for name in kb_sources))
    if detector_counts:
        lines.extend(["## Detection summary", "", "| Detector | Findings |", "| --- | ---: |"])
        detector_labels = {
            "static-analysis": "Python AST analysis",
            "c-family-taint-analysis": "C/C++ source-to-sink analysis",
            "local-llm": "Local Ollama model (accepted by evidence gate)",
        }
        lines.extend(f"| {detector_labels.get(name, name)} | {count} |"
                     for name, count in sorted(detector_counts.items()))
        lines.append("")
    if metadata.get("model") != "disabled":
        lines.extend(["## Local model diagnostics", "",
                      f"- Model proposals: {model_metrics.get('proposed', 0)}",
                      f"- Accepted by evidence gate: {model_metrics.get('accepted', 0)}",
                      f"- Unique model-only findings added: {model_metrics.get('unique_additions', 0)}",
                      f"- Model findings matching static findings: {model_metrics.get('duplicates_of_static', 0)}",
                      f"- Repeated model proposals: {model_metrics.get('duplicate_model_proposals', 0)}",
                      f"- Rejected by evidence gate: {model_metrics.get('rejected', 0)}",
                      f"- Ollama requests: {model_metrics.get('requests', 0)}"])
        reasons = model_metrics.get("rejection_reasons", {})
        if reasons:
            lines.append("- Rejection reasons: " + ", ".join(f"{key} ({value})" for key, value in sorted(reasons.items())))
        match_modes = model_metrics.get("evidence_match_modes", {})
        if match_modes:
            lines.append("- Evidence match modes: " + ", ".join(
                f"{key} ({value})" for key, value in sorted(match_modes.items())))
        if metadata.get("llm_error"):
            lines.append(f"- Model error: {metadata['llm_error']}")
        lines.append("")
    if severity_counts:
        lines.extend(["## Findings by severity", "", "| Severity | Count |", "| --- | ---: |"])
        lines.extend(f"| {severity} | {count} |" for severity, count in sorted(severity_counts.items()))
        lines.append("")
    if counts:
        lines.extend(["## Findings by CWE", "", "| CWE | Count |", "| --- | ---: |"])
        lines.extend(f"| {cwe} | {count} |" for cwe, count in sorted(counts.items()))
        lines.append("")
    if not findings:
        lines.append("No supported vulnerability patterns were reported.")
    for finding in findings:
        lines.extend([
            f"## {finding.get('title', 'Finding')} ({finding.get('cwe', 'CWE-?')})", "",
            f"- **Location:** `{finding.get('file')}:{finding.get('line')}`",
            f"- **Severity:** {finding.get('severity', 'medium')}",
            f"- **Confidence:** {finding.get('confidence', 0.0)}",
            f"- **Detected by:** {finding.get('source', 'unknown')}",
            f"- **Evidence:** `{finding.get('evidence', '')}`",
            f"- **Reason:** {finding.get('reason', '')}",
            f"- **Recommendation:** {finding.get('recommendation', '')}",
        ])
        refs = finding.get("references", [])
        if refs:
            reference = refs[0]
            reference_label = "Local CWE reference" if reference.get("cwe") == finding.get("cwe") else "Related local reference"
            lines.append(f"- **{reference_label}:** {reference.get('cwe')} {reference.get('title')}")
            method = {"exact_cwe": "Exact CWE match", "bm25": "BM25 text match"}.get(
                reference.get("retrieval_method"))
            if method:
                lines.append(f"- **Retrieval method:** {method}")
            if kb_file := reference.get("knowledge_base_file"):
                lines.append(f"- **Knowledge-base file:** `{kb_file}`")
            if source := reference.get("source"):
                lines.append(f"- **Reference source:** {source}")
            if reference.get("cwe") == finding.get("cwe"):
                description = str(reference.get("description", "")).strip()
                mitigation = str(reference.get("mitigation", "")).strip()
                safe_example = str(reference.get("safe", "")).strip()
                if description:
                    lines.append(f"- **CWE description:** {description[:600]}")
                if mitigation:
                    lines.append(f"- **Knowledge-base mitigation:** {mitigation[:800]}")
                if safe_example:
                    lines.extend(["", "**Safer example from the local knowledge base:**", ""])
                    lines.extend("    " + part for part in safe_example[:1200].splitlines())
                    lines.append("")
                cves = reference.get("cves", [])
                if cves:
                    cve_text = ", ".join(str(cve) for cve in cves[:5])
                    lines.append("- **CVE examples listed for this CWE (not verified against this code):** " + cve_text)
        lines.append("")
    (out_dir / "report.md").write_text("\n".join(lines), encoding="utf-8")
