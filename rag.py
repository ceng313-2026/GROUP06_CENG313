"""Local BM25 retrieval with adapters for SecureGuard and MITRE-style CWE JSON.

Accepted sources include JSONL (one object per line), a JSON array of objects,
or a JSON object containing a records/entries/items list. Common field aliases
from the teammate project's KB (name/desc/bad/good/lang/cves) are normalized to
SecureGuard's canonical shape at load time.
"""
from __future__ import annotations

import json
import math
import re
from collections import Counter
from pathlib import Path
from typing import Any, Iterable


TOKEN = re.compile(r"(?:CWE|CVE)-\d+(?:-\d+)?|[A-Za-z_][A-Za-z0-9_]*|\d+", re.I)
CAMEL = re.compile(r"[A-Z]+(?=[A-Z][a-z]|\b)|[A-Z]?[a-z]+|\d+")
STOP_WORDS = {
    "the", "a", "an", "of", "to", "and", "or", "in", "is", "it", "for", "if",
    "else", "return", "this", "that", "with", "as", "by", "on", "be", "are",
    "from", "can", "may", "not", "int", "var", "let", "def", "void", "self",
    "char", "const", "string", "public", "private", "class", "function", "true", "false",
}
LANG_ALIASES = {
    "py": "python", "python3": "python", "c++": "cpp", "cc": "cpp", "hpp": "cpp",
    "hxx": "cpp", "h": "c", "cxx": "cpp", "js": "javascript", "ts": "javascript",
    "typescript": "javascript", "node": "javascript", "c#": "csharp", "cs": "csharp",
    "golang": "go", "rs": "rust", "": "",
}
EXT_LANG = {
    ".py": "python", ".c": "c", ".h": "c", ".cc": "cpp", ".cpp": "cpp",
    ".cxx": "cpp", ".hpp": "cpp", ".hxx": "cpp",
}
RECORD_LIST_KEYS = ("records", "entries", "items", "weaknesses", "knowledge_base", "data")


def normalize_language(language: Any) -> str:
    """Normalize common language names; an empty value means language-neutral."""
    value = str(language or "").strip().lower()
    return LANG_ALIASES.get(value, value)


def language_for_path(path: str | Path) -> str:
    return EXT_LANG.get(Path(path).suffix.lower(), "")


def tokens(text: str) -> list[str]:
    """Tokenize CWE/CVE IDs, identifiers, and camelCase components."""
    result: list[str] = []
    for raw in TOKEN.findall(text or ""):
        lowered = raw.lower()
        if lowered.startswith(("cwe-", "cve-")):
            result.append(lowered)
            result.extend(part for part in re.split(r"[-_]", lowered) if part)
            continue
        parts = [part.lower() for part in CAMEL.findall(raw.replace("_", " "))]
        if lowered not in STOP_WORDS and len(lowered) > 1:
            result.append(lowered)
        result.extend(part for part in parts if len(part) > 1 and part not in STOP_WORDS and part != lowered)
    return result


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, list):
        return ", ".join(text for item in value if (text := _as_text(item)))
    if isinstance(value, dict):
        return json.dumps(value, ensure_ascii=False)
    return str(value).strip()


def _first_text(record: dict[str, Any], *names: str) -> str:
    for name in names:
        value = _as_text(record.get(name))
        if value:
            return value
    return ""


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [text for item in value if (text := _as_text(item))]
    if isinstance(value, (tuple, set)):
        return [text for item in value if (text := _as_text(item))]
    if isinstance(value, str):
        # Keywords are usually JSON arrays, but accept comma/semicolon-delimited text too.
        return [part.strip() for part in re.split(r"[,;\n]", value) if part.strip()]
    return [_as_text(value)]


def _canonical_record(record: dict[str, Any]) -> dict[str, Any] | None:
    raw_id = _first_text(record, "id", "record_id", "recordId")
    raw_cwe = _first_text(record, "cwe", "CWE", "weakness_id", "weaknessId")
    cwe_match = re.search(r"CWE\s*-?\s*(\d{1,5})", raw_cwe, re.I)
    if not cwe_match:
        cwe_match = re.search(r"CWE\s*-?\s*(\d{1,5})", raw_id, re.I)
    if cwe_match:
        cwe = f"CWE-{int(cwe_match.group(1))}"
    elif raw_cwe.isdigit():
        cwe = f"CWE-{int(raw_cwe)}"
    else:
        return None

    title = _first_text(record, "title", "name", "weakness_name", "weaknessName", "summary")
    description = _first_text(record, "description", "desc", "extended_description", "extendedDescription", "details")
    unsafe = _first_text(record, "unsafe", "bad", "vulnerable", "vulnerable_example", "vulnerableExample")
    safe = _first_text(record, "safe", "good", "secure_example", "secureExample", "remediation_example")
    mitigation = _first_text(record, "mitigation", "recommendation", "remediation", "fix", "solution")
    keywords = _as_list(record.get("keywords", record.get("tags", [])))
    cves = _as_list(record.get("cves", record.get("CVE", record.get("cve", []))))
    language = normalize_language(_first_text(record, "lang", "language", "programming_language", "programmingLanguage"))
    source = _first_text(record, "source", "origin")

    # Keep unknown fields for traceability, while exposing canonical aliases to retrieval/reporting.
    normalized = dict(record)
    normalized.update({
        "cwe": cwe,
        "title": title or cwe,
        "keywords": keywords,
        "description": description,
        "unsafe": unsafe,
        "safe": safe,
        "mitigation": mitigation,
        "lang": language,
        "cves": cves,
        "source": source,
        "record_id": raw_id,
    })
    return normalized


def _extract_rows(data: Any) -> list[Any]:
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in RECORD_LIST_KEYS:
            nested = data.get(key)
            if isinstance(nested, list):
                return nested
        if any(key in data for key in ("cwe", "CWE", "id", "record_id", "recordId")):
            return [data]
        # Also accept object maps such as {"CWE-79": {...}, "CWE-89": {...}}.
        rows: list[Any] = []
        for key, value in data.items():
            if isinstance(value, dict):
                row = dict(value)
                row.setdefault("cwe", key)
                rows.append(row)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        row = dict(item)
                        row.setdefault("cwe", key)
                        rows.append(row)
        return rows
    return []


def _load_rows(path: Path) -> tuple[list[Any], int]:
    text = path.read_text(encoding="utf-8-sig")
    try:
        return _extract_rows(json.loads(text)), 0
    except json.JSONDecodeError:
        rows: list[Any] = []
        invalid = 0
        for line in text.splitlines():
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                invalid += 1
                continue
            if isinstance(item, list):
                rows.extend(item)
            elif isinstance(item, dict):
                rows.append(item)
            else:
                invalid += 1
        return rows, invalid


class LocalRAG:
    """Dependency-free BM25 index over normalized CWE records."""

    def __init__(self, records: list[dict[str, Any]], load_stats: dict[str, Any] | None = None):
        canonical: list[dict[str, Any]] = []
        seen: set[tuple[Any, ...]] = set()
        invalid = duplicate_count = 0
        for raw in records:
            if not isinstance(raw, dict):
                invalid += 1
                continue
            row = _canonical_record(raw)
            if row is None:
                invalid += 1
                continue
            signature = (
                row["cwe"], row["lang"], row["title"].casefold(),
                row["description"].casefold(), row["unsafe"].casefold(), row["safe"].casefold(),
                row["mitigation"].casefold(), tuple(sorted(value.casefold() for value in row["keywords"])),
                tuple(sorted(value.casefold() for value in row["cves"])),
            )
            if signature in seen:
                duplicate_count += 1
                continue
            seen.add(signature)
            canonical.append(row)
        if not canonical:
            raise ValueError("The knowledge base contains no usable CWE records.")

        self.records = canonical
        self.docs: list[Counter[str]] = []
        self.doc_lengths: list[int] = []
        df: Counter[str] = Counter()
        for row in canonical:
            searchable = " ".join(str(row.get(key, "")) for key in (
                "cwe", "title", "keywords", "description", "unsafe", "safe", "mitigation", "cves"))
            counts = Counter(tokens(searchable))
            self.docs.append(counts)
            self.doc_lengths.append(sum(counts.values()))
            df.update(counts.keys())
        n = max(len(canonical), 1)
        self.idf = {term: math.log(1 + (n - count + 0.5) / (count + 0.5)) for term, count in df.items()}
        self.avgdl = (sum(self.doc_lengths) / len(self.doc_lengths)) if self.doc_lengths else 1.0
        supplied_stats = load_stats or {}
        languages = Counter(row.get("lang", "") or "general" for row in canonical)
        self.load_stats = {
            "raw_records": supplied_stats.get("raw_records", len(records)),
            "loaded_records": len(canonical),
            "invalid_records": supplied_stats.get("invalid_records", 0) + invalid,
            "duplicates_removed": supplied_stats.get("duplicates_removed", 0) + duplicate_count,
            "unique_cwes": len({row["cwe"] for row in canonical}),
            "languages": dict(sorted(languages.items())),
            "sources": supplied_stats.get("sources", []),
        }

    @classmethod
    def from_file(cls, path: Path) -> "LocalRAG":
        return cls.from_files([path])

    @classmethod
    def from_files(cls, paths: Iterable[Path]) -> "LocalRAG":
        rows: list[Any] = []
        malformed = 0
        source_names: list[str] = []
        for path in paths:
            loaded, skipped = _load_rows(Path(path))
            rows.extend({**row, "knowledge_base_file": Path(path).name}
                        if isinstance(row, dict) else row for row in loaded)
            malformed += skipped
            source_names.append(Path(path).name)
        return cls(rows, load_stats={
            "raw_records": len(rows) + malformed,
            "invalid_records": malformed,
            "sources": source_names,
        })

    @staticmethod
    def _language_compatible(record_language: str, requested_language: str) -> bool:
        if not requested_language or not record_language or record_language == requested_language:
            return True
        # C examples are useful for C++; C++ examples are not assumed valid C.
        return requested_language == "cpp" and record_language == "c"

    def lookup_cwe(self, cwe: str, lang: str | None = None) -> dict[str, Any] | None:
        """Return the best exact-CWE entry, preferring examples for the source language."""
        match = re.fullmatch(r"\s*CWE\s*-?\s*(\d{1,5})\s*", str(cwe), re.I)
        if not match:
            return None
        wanted = f"CWE-{int(match.group(1))}"
        requested_language = normalize_language(lang)
        candidates = [row for row in self.records if row.get("cwe") == wanted and
                      self._language_compatible(row.get("lang", ""), requested_language)]
        if not candidates:
            return None

        def rank(row: dict[str, Any]) -> tuple[int, int, int]:
            row_language = row.get("lang", "")
            language_rank = (0 if requested_language and row_language == requested_language else
                             1 if not row_language else 2)
            example_completeness = sum(bool(row.get(field)) for field in
                                       ("mitigation", "description", "unsafe", "safe", "cves"))
            # Prefer a useful, language-compatible record when a CWE has multiple examples.
            description_length = min(len(_as_text(row.get("description"))), 1500)
            return language_rank, -example_completeness, -description_length

        return {**min(candidates, key=rank), "score": 100.0, "retrieval_method": "exact_cwe"}

    def search(self, query: str, limit: int = 3, lang: str | None = None) -> list[dict[str, Any]]:
        requested_language = normalize_language(lang)
        query_counts = Counter(tokens(query))
        if not query_counts or limit <= 0:
            return []
        ranked: list[tuple[float, int]] = []
        for index, row in enumerate(self.records):
            row_language = row.get("lang", "")
            if not self._language_compatible(row_language, requested_language):
                continue
            doc = self.docs[index]
            length = self.doc_lengths[index]
            score = 0.0
            for term, query_frequency in query_counts.items():
                frequency = doc.get(term, 0)
                if not frequency:
                    continue
                k1, b = 1.5, 0.75
                norm = frequency + k1 * (1 - b + b * length / self.avgdl)
                score += self.idf.get(term, 0) * (frequency * (k1 + 1) / norm) * (1 + math.log(query_frequency))
            if score <= 0:
                continue
            if requested_language and row_language == requested_language:
                score *= 1.35
            elif requested_language and row_language == "":
                score *= 1.0
            elif requested_language == "cpp" and row_language == "c":
                score *= 0.92
            ranked.append((score, index))
        ranked.sort(key=lambda result: (-result[0], result[1]))

        # Multiple code samples for one CWE must not crowd out other weaknesses.
        hits: list[dict[str, Any]] = []
        seen_cwes: set[str] = set()
        for score, index in ranked:
            row = self.records[index]
            cwe = row.get("cwe", "CWE-?")
            if cwe in seen_cwes:
                continue
            seen_cwes.add(cwe)
            hits.append({**row, "score": round(score, 3), "retrieval_method": "bm25"})
            if len(hits) >= limit:
                break
        return hits

    @staticmethod
    def _clip(value: Any, limit: int) -> str:
        text = _as_text(value)
        if len(text) <= limit:
            return text
        return text[:limit].rstrip() + " …"

    def context(self, query: str, limit: int = 3, lang: str | None = None,
                max_chars: int = 5200, preferred_cwes: Iterable[str] | None = None) -> str:
        if limit <= 0:
            return "No matching local security references were retrieved."
        # Findings already have a CWE from the static analyzer. Include those exact
        # references before broad source-level matches so the LLM sees relevant guidance.
        hits: list[dict[str, Any]] = []
        seen_cwes: set[str] = set()
        for cwe in preferred_cwes or ():
            item = self.lookup_cwe(cwe, lang=lang)
            if item and item["cwe"] not in seen_cwes:
                hits.append(item)
                seen_cwes.add(item["cwe"])
                if len(hits) >= limit:
                    break
        if len(hits) < limit:
            for item in self.search(query, limit=limit, lang=lang):
                if item["cwe"] not in seen_cwes:
                    hits.append(item)
                    seen_cwes.add(item["cwe"])
                    if len(hits) >= limit:
                        break
        if not hits:
            return "No matching local security references were retrieved."
        blocks: list[str] = []
        for item in hits:
            block = [f"[{item.get('cwe')} — {self._clip(item.get('title'), 180)}]"]
            description = self._clip(item.get("description"), 440)
            if description:
                block.append(f"Description: {description}")
            unsafe = self._clip(item.get("unsafe"), 300)
            if unsafe:
                block.append(f"Vulnerable pattern: {unsafe}")
            safe = self._clip(item.get("safe"), 300)
            if safe:
                block.append(f"Safer pattern: {safe}")
            mitigation = self._clip(item.get("mitigation"), 300)
            if mitigation and mitigation != safe:
                block.append(f"Mitigation: {mitigation}")
            cves = _as_list(item.get("cves"))
            if cves:
                block.append("Related CVEs: " + ", ".join(cves[:4]))
            if item.get("lang"):
                block.append(f"Example language: {item['lang']}")
            blocks.append("\n".join(block))
        result = "\n\n---\n\n".join(blocks)
        if len(result) > max_chars:
            result = result[:max_chars].rstrip() + " …"
        return result
