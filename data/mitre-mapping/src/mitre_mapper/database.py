from __future__ import annotations

import hashlib
import json
import math
import re
from collections import Counter
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
TOKEN_RE = re.compile(r"[a-z0-9]+(?:[._/-][a-z0-9]+)*", re.IGNORECASE)
SUPPORTED_OPERATORS = {
    "equals",
    "contains_any",
    "exists",
    "in",
    "greater_than_or_equal",
    "matches_regex",
}
EVIDENCE_FIELDS = {
    "producer",
    "data_source",
    "event",
    "source",
    "target",
    "severity",
    "network",
    "http",
    "dns",
    "tls",
    "file",
    "user",
    "derived",
}


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def tokenize(text: str) -> list[str]:
    return [match.group(0).lower() for match in TOKEN_RE.finditer(text or "")]


def _merge(base: Any, override: Any) -> Any:
    if isinstance(base, dict) and isinstance(override, dict):
        merged = deepcopy(base)
        for key, value in override.items():
            merged[key] = _merge(merged.get(key), value)
        return merged
    return deepcopy(override)


def apply_overrides(records: list[dict[str, Any]], overrides: dict[str, Any]) -> list[dict[str, Any]]:
    output = []
    seen = set()
    for record in records:
        technique_id = record.get("technique_id")
        output.append(_merge(record, overrides.get(technique_id, {})))
        seen.add(technique_id)
    for technique_id, override in overrides.items():
        if technique_id not in seen and isinstance(override, dict) and override.get("name"):
            output.append(_merge({"technique_id": technique_id}, override))
    return output


def validate_database(records: Any) -> dict[str, list[str]]:
    errors: list[str] = []
    warnings: list[str] = []
    if not isinstance(records, list) or not records:
        return {"errors": ["Database must be a non-empty JSON array."], "warnings": []}

    ids: list[str] = []
    for index, item in enumerate(records):
        label = item.get("technique_id", f"record[{index}]") if isinstance(item, dict) else f"record[{index}]"
        if not isinstance(item, dict):
            errors.append(f"{label}: must be an object")
            continue
        technique_id = item.get("technique_id")
        if not isinstance(technique_id, str) or not TECHNIQUE_ID_RE.fullmatch(technique_id):
            errors.append(f"{label}: invalid technique_id")
        else:
            ids.append(technique_id)
        for key in ("schema_version", "name", "description", "source_metadata"):
            if not item.get(key):
                errors.append(f"{label}: missing {key}")
        if not item.get("retrieval_text") and not item.get("behavioral_indicators") and not item.get("retrieval_keywords"):
            errors.append(f"{label}: all optimized retrieval fields are empty")
        metadata = item.get("source_metadata") or {}
        if not metadata.get("attack_version") or not metadata.get("source_url"):
            errors.append(f"{label}: incomplete source_metadata")

        rule_ids: set[str] = set()
        for group in ("required_evidence", "positive_evidence", "negative_evidence", "exclusion_indicators"):
            rules = item.get(group, [])
            if not isinstance(rules, list):
                errors.append(f"{label}: {group} must be an array")
                continue
            for rule in rules:
                rule_id = rule.get("rule_id")
                if not rule_id:
                    errors.append(f"{label}: evidence rule without rule_id in {group}")
                elif rule_id in rule_ids:
                    errors.append(f"{label}: duplicate evidence rule {rule_id}")
                rule_ids.add(rule_id)
                operator = rule.get("operator")
                if operator not in SUPPORTED_OPERATORS:
                    errors.append(f"{label}/{rule_id}: unsupported operator {operator!r}")
                field = rule.get("field", "")
                if not field or field.split(".", 1)[0] not in EVIDENCE_FIELDS:
                    errors.append(f"{label}/{rule_id}: unsupported evidence field {field!r}")
                if group != "exclusion_indicators":
                    weight = rule.get("weight")
                    if not isinstance(weight, (int, float)) or not -1.0 <= float(weight) <= 1.0:
                        errors.append(f"{label}/{rule_id}: weight must be between -1 and 1")
                    if group == "negative_evidence" and isinstance(weight, (int, float)) and weight > 0:
                        errors.append(f"{label}/{rule_id}: negative evidence weight must be <= 0")

    duplicates = sorted(value for value, count in Counter(ids).items() if count > 1)
    if duplicates:
        errors.append(f"Duplicate technique IDs: {', '.join(duplicates)}")
    known = set(ids)
    for item in records:
        if not isinstance(item, dict):
            continue
        label = item.get("technique_id", "unknown")
        parent = (item.get("parent_technique") or {}).get("technique_id")
        if parent and parent not in known:
            errors.append(f"{label}: parent {parent} is not present")
        for child in item.get("sub_techniques", []):
            child_id = child.get("technique_id") if isinstance(child, dict) else None
            if child_id and child_id not in known:
                warnings.append(f"{label}: declared sub-technique {child_id} is outside the supported subset")
        for other in item.get("confusable_techniques", []):
            other_id = other.get("technique_id") if isinstance(other, dict) else None
            if other_id and other_id not in known:
                warnings.append(f"{label}: confusable technique {other_id} is outside the supported subset")
    return {"errors": sorted(set(errors)), "warnings": sorted(set(warnings))}


def _names(values: Iterable[Any]) -> list[str]:
    result: list[str] = []
    for value in values or []:
        if isinstance(value, str):
            result.append(value)
        elif isinstance(value, dict):
            candidate = value.get("name") or value.get("entity_name") or value.get("technique_id")
            if candidate:
                result.append(str(candidate))
    return result


def build_document(item: dict[str, Any]) -> dict[str, Any]:
    technique_id = item["technique_id"]
    name = item["name"]
    behaviors = [str(value) for value in item.get("behavioral_indicators", []) if value]
    procedures = item.get("procedure_examples", [])[:8]
    procedure_summaries = []
    for procedure in procedures:
        text = procedure.get("behavior_summary") or procedure.get("procedure_description") or ""
        if text:
            procedure_summaries.append(re.sub(r"\s+", " ", text).strip())

    distinction_parts: list[str] = []
    for relation in item.get("confusable_techniques", []):
        distinction = relation.get("distinction") or {}
        current = distinction.get("current_technique_when") or []
        if current:
            distinction_parts.append(" ".join(str(value) for value in current[:2]))
    dense_parts = [f"Technique: {technique_id} {name}."]
    if behaviors:
        dense_parts.append("Behavioral indicators: " + "; ".join(behaviors) + ".")
    elif item.get("retrieval_text"):
        dense_parts.append(str(item["retrieval_text"]))
    else:
        dense_parts.append(re.sub(r"\s+", " ", item.get("description", "")).strip()[:1800])
    if distinction_parts:
        dense_parts.append("Distinguishing conditions: " + " ".join(distinction_parts))
    if procedure_summaries:
        dense_parts.append("Representative procedures: " + " ".join(procedure_summaries))
    dense_text = " ".join(dense_parts)

    tools = _names(item.get("associated_tools", []))
    procedure_names = _names(procedures)
    sparse_parts = [technique_id, name]
    sparse_parts.extend(str(value) for value in item.get("aliases", []))
    sparse_parts.extend(str(value) for value in item.get("retrieval_keywords", []))
    sparse_parts.extend(behaviors)
    sparse_parts.extend(tools)
    sparse_parts.extend(procedure_names)
    if len(sparse_parts) <= 2:
        sparse_parts.append(item.get("retrieval_text") or item.get("description", ""))

    parent = item.get("parent_technique") or {}
    payload = {
        "technique_id": technique_id,
        "name": name,
        "tactics": [value.get("tactic_id", value.get("name")) for value in item.get("tactics", []) if isinstance(value, dict)],
        "platforms": item.get("platforms", []),
        "data_sources": item.get("data_sources", []),
        "parent_id": parent.get("technique_id"),
        "sub_technique_ids": [value.get("technique_id") for value in item.get("sub_techniques", []) if isinstance(value, dict)],
        "confusable_ids": [value.get("technique_id") for value in item.get("confusable_techniques", []) if isinstance(value, dict)],
        "confusable_techniques": item.get("confusable_techniques", []),
        "required_evidence": item.get("required_evidence", []),
        "positive_evidence": item.get("positive_evidence", []),
        "negative_evidence": item.get("negative_evidence", []),
        "exclusion_indicators": item.get("exclusion_indicators", []),
        "mapping_guidance": item.get("mapping_guidance", {}),
        "attack_version": (item.get("source_metadata") or {}).get("attack_version"),
        "dense_text": dense_text,
    }
    return {
        "technique_id": technique_id,
        "name": name,
        "dense_text": dense_text,
        "sparse_text": " ".join(value for value in sparse_parts if value),
        "payload": payload,
    }


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as stream:
        for row in rows:
            stream.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as stream:
        return [json.loads(line) for line in stream if line.strip()]


def build_bm25_index(documents: list[dict[str, Any]], k1: float = 1.5, b: float = 0.75) -> dict[str, Any]:
    tokenized = [tokenize(document["sparse_text"]) for document in documents]
    doc_count = len(tokenized)
    average_length = sum(map(len, tokenized)) / max(doc_count, 1)
    document_frequency: Counter[str] = Counter()
    for tokens in tokenized:
        document_frequency.update(set(tokens))
    terms = sorted(document_frequency)
    token_to_index = {term: index for index, term in enumerate(terms)}
    idf = {
        term: math.log(1.0 + (doc_count - frequency + 0.5) / (frequency + 0.5))
        for term, frequency in document_frequency.items()
    }
    vectors: dict[str, dict[str, list[float] | list[int]]] = {}
    for document, tokens in zip(documents, tokenized):
        frequencies = Counter(tokens)
        denominator_length = k1 * (1.0 - b + b * len(tokens) / max(average_length, 1.0))
        weighted = []
        for term, frequency in frequencies.items():
            weight = idf[term] * (frequency * (k1 + 1.0)) / (frequency + denominator_length)
            weighted.append((token_to_index[term], weight))
        weighted.sort()
        vectors[document["technique_id"]] = {
            "indices": [value[0] for value in weighted],
            "values": [round(value[1], 8) for value in weighted],
        }
    return {
        "method": "bm25",
        "k1": k1,
        "b": b,
        "document_count": doc_count,
        "average_document_length": average_length,
        "token_to_index": token_to_index,
        "idf": idf,
        "document_vectors": vectors,
    }


def build_query_vector(text: str, index: dict[str, Any]) -> dict[str, list[float] | list[int]]:
    terms = set(tokenize(text))
    pairs = sorted(
        (index["token_to_index"][term], 1.0)
        for term in terms
        if term in index["token_to_index"]
    )
    return {"indices": [value[0] for value in pairs], "values": [value[1] for value in pairs]}


def prepare_database(project_root: Path, source_path: Path) -> dict[str, Any]:
    overrides = read_json(project_root / "configs" / "technique_overrides.json")
    source_records = read_json(source_path)
    records = apply_overrides(source_records, overrides)
    validation = validate_database(records)
    if validation["errors"]:
        raise ValueError("Database validation failed:\n- " + "\n- ".join(validation["errors"]))

    database_path = project_root / "artifacts" / "attack" / "attack_final.mapping.json"
    documents_path = project_root / "artifacts" / "retrieval" / "technique_documents.jsonl"
    procedures_path = project_root / "artifacts" / "retrieval" / "procedure_documents.jsonl"
    bm25_path = project_root / "artifacts" / "retrieval" / "bm25_index.json"
    manifest_path = project_root / "artifacts" / "attack" / "index_manifest.json"
    write_json(database_path, records)
    documents = [build_document(item) for item in records]
    write_jsonl(documents_path, documents)

    procedure_documents: list[dict[str, Any]] = []
    for item in records:
        for order, procedure in enumerate(item.get("procedure_examples", [])):
            procedure_documents.append({
                "technique_id": item["technique_id"],
                "procedure_order": order,
                "entity_id": procedure.get("entity_id"),
                "entity_name": procedure.get("entity_name"),
                "text": procedure.get("behavior_summary") or procedure.get("procedure_description") or "",
                "source": procedure.get("source"),
            })
    write_jsonl(procedures_path, procedure_documents)
    bm25 = build_bm25_index(documents)
    write_json(bm25_path, bm25)

    attack_versions = sorted({(item.get("source_metadata") or {}).get("attack_version") for item in records})
    revision_path = project_root.parent / "tei" / "models--basel--ATTACK-BERT" / "refs" / "main"
    revision = revision_path.read_text(encoding="utf-8").strip() if revision_path.is_file() else "unknown"
    manifest = {
        "index_version": "1.0.0",
        "attack_schema_version": records[0].get("schema_version"),
        "attack_version": attack_versions[0] if len(attack_versions) == 1 else attack_versions,
        "source_attack_final_sha256": sha256_file(source_path),
        "attack_final_sha256": sha256_file(database_path),
        "embedding_model": "basel/ATTACK-BERT",
        "embedding_model_revision": revision,
        "sparse_method": "bm25",
        "document_builder_version": "1.0.0",
        "technique_count": len(records),
        "procedure_count": len(procedure_documents),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "validation_warnings": validation["warnings"],
    }
    write_json(manifest_path, manifest)
    return manifest
