"""Remove ATT&CK identifier leakage from alert inputs.

The baselines must judge behavior from observable alert fields, not from
MITRE metadata that a sensor rule may already declare. This module strips:

* every field whose key mentions ``mitre``;
* explicit tactic/technique fields such as ``mitre_technique_id`` or ``tactic``;
* ATT&CK-looking list items and tag values (``T1046``, ``TA0007``, ``attack.t1046``);
* MITRE-labelled lines inside free text plus inline ATT&CK id tokens.

Every removal is recorded so the benchmark manifest can prove no leakage.
"""

from __future__ import annotations

import json
import re
from typing import Any


SANITIZER_VERSION = "1.0.0"

ATTACK_ID_IN_TEXT_RE = re.compile(r"(?<![A-Za-z0-9])(?:T\d{4}(?:\.\d{3})?|TA\d{4})(?![A-Za-z0-9])")
ATTACK_ID_RE = re.compile(r"^(?:T\d{4}(?:\.\d{3})?|TA\d{4})$", re.IGNORECASE)
MITRE_LABEL_RE = re.compile(r"\b(mitre|att&ck|attack)\b", re.IGNORECASE)

SENSITIVE_KEYS = {
    "tactic",
    "tactics",
    "tactic_id",
    "tactic_ids",
    "tacticid",
    "tacticids",
    "technique",
    "techniques",
    "technique_id",
    "technique_ids",
    "techniqueid",
    "techniqueids",
    "attack_pattern",
    "attackpattern",
    "attack_technique",
    "attack_techniques",
}


def _normalize_key(key: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(key).lower()).strip("_")


def is_sensitive_key(key: str) -> bool:
    normalized = _normalize_key(key)
    return "mitre" in normalized or normalized in SENSITIVE_KEYS


def looks_like_attack_id(value: str) -> bool:
    return bool(ATTACK_ID_RE.match(str(value).strip()))


def looks_like_attack_tag(value: str) -> bool:
    text = str(value).strip()
    if not text:
        return False
    lowered = text.lower()
    if looks_like_attack_id(text):
        return True
    if lowered.startswith("attack.") or lowered.startswith("mitre."):
        return True
    if "mitre" in lowered:
        return True
    return bool(ATTACK_ID_IN_TEXT_RE.search(text)) and len(text.split()) <= 4


def _scrub_text(text: str, scrub_inline_ids: bool) -> tuple[str, list[str]]:
    hits: list[str] = []
    kept_lines: list[str] = []
    for line in str(text).splitlines():
        label = line.split(":", 1)[0] if ":" in line else ""
        if label and MITRE_LABEL_RE.search(label):
            hits.append(line.strip()[:200])
            continue
        kept_lines.append(line)
    result = "\n".join(kept_lines)
    if scrub_inline_ids:
        def replace(match: re.Match[str]) -> str:
            hits.append(match.group(0))
            return ""

        result = ATTACK_ID_IN_TEXT_RE.sub(replace, result)
        result = re.sub(r"[ \t]{2,}", " ", result)
        result = re.sub(r"\n{3,}", "\n\n", result)
    return result, [hit for hit in hits if hit]


def _preview(value: Any) -> Any:
    if isinstance(value, str):
        return value[:200]
    try:
        rendered = json.dumps(value, ensure_ascii=False)
    except (TypeError, ValueError):
        rendered = str(value)
    return rendered[:200]


def sanitize_alert(
    alert: dict[str, Any], *, scrub_inline_ids: bool = True,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return a cleaned alert and a report of every removed ATT&CK hint."""

    removed_fields: list[dict[str, Any]] = []
    scrubbed_values: list[dict[str, Any]] = []

    def walk(value: Any, path: str) -> Any:
        if isinstance(value, dict):
            output: dict[str, Any] = {}
            for key, item in value.items():
                child_path = f"{path}.{key}" if path else str(key)
                if is_sensitive_key(key):
                    removed_fields.append({
                        "path": child_path,
                        "key": str(key),
                        "reason": "mitre_or_attack_field_name",
                        "value_preview": _preview(item),
                    })
                    continue
                output[key] = walk(item, child_path)
            return output
        if isinstance(value, list):
            output_list: list[Any] = []
            for index, item in enumerate(value):
                child_path = f"{path}[{index}]"
                if isinstance(item, str) and looks_like_attack_tag(item):
                    removed_fields.append({
                        "path": child_path,
                        "key": "",
                        "reason": "attack_identifier_list_item",
                        "value_preview": _preview(item),
                    })
                    continue
                output_list.append(walk(item, child_path))
            return output_list
        if isinstance(value, str):
            cleaned, hits = _scrub_text(value, scrub_inline_ids)
            if hits:
                scrubbed_values.append({
                    "path": path,
                    "removed": hits,
                    "value_preview": _preview(value),
                })
            return cleaned
        return value

    cleaned = walk(alert, "")
    report = {
        "sanitizer_version": SANITIZER_VERSION,
        "removed_fields": removed_fields,
        "scrubbed_values": scrubbed_values,
        "counts": {
            "removed_fields": len(removed_fields),
            "scrubbed_values": len(scrubbed_values),
        },
    }
    return cleaned, report
