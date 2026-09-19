from __future__ import annotations

import re
from typing import Any


MISSING = object()


def field_value(document: dict[str, Any], dotted_path: str) -> Any:
    value: Any = document
    for part in dotted_path.split("."):
        if not isinstance(value, dict) or part not in value:
            return MISSING
        value = value[part]
    return value


def _casefold(value: Any) -> Any:
    return value.casefold() if isinstance(value, str) else value


def rule_matches(rule: dict[str, Any], alert: dict[str, Any]) -> bool:
    actual = field_value(alert, rule.get("field", ""))
    operator = rule.get("operator")
    expected = rule.get("value")
    if operator == "exists":
        exists = actual is not MISSING and actual is not None
        return exists is bool(expected)
    if actual is MISSING or actual is None:
        return False
    if operator == "equals":
        return _casefold(actual) == _casefold(expected)
    if operator == "contains_any":
        needles = expected if isinstance(expected, list) else [expected]
        haystacks = actual if isinstance(actual, list) else [actual]
        return any(
            str(needle).casefold() in str(haystack).casefold()
            for haystack in haystacks
            for needle in needles
            if needle is not None
        )
    if operator == "in":
        choices = expected if isinstance(expected, list) else [expected]
        actual_values = actual if isinstance(actual, list) else [actual]
        folded = {_casefold(value) for value in choices}
        return any(_casefold(value) in folded for value in actual_values)
    if operator == "greater_than_or_equal":
        try:
            return float(actual) >= float(expected)
        except (TypeError, ValueError):
            return False
    if operator == "matches_regex":
        try:
            return re.search(str(expected), str(actual), flags=re.IGNORECASE) is not None
        except re.error:
            return False
    return False


def _evidence_record(rule: dict[str, Any], alert: dict[str, Any]) -> dict[str, Any]:
    value = field_value(alert, rule["field"])
    return {
        "rule_id": rule.get("rule_id"),
        "field": rule["field"],
        "value": None if value is MISSING else value,
        "weight": rule.get("weight", 0.0),
        "reason": rule.get("reason", ""),
    }


def evaluate_evidence(payload: dict[str, Any], alert: dict[str, Any]) -> dict[str, Any]:
    required = payload.get("required_evidence", [])
    required_matches = [rule_matches(rule, alert) for rule in required]
    required_passed = all(required_matches) if required else True
    matched_required = [
        _evidence_record(rule, alert)
        for rule, matched in zip(required, required_matches)
        if matched
    ]

    exclusions = payload.get("exclusion_indicators", [])
    matched_exclusions = [_evidence_record(rule, alert) for rule in exclusions if rule_matches(rule, alert)]
    positives = payload.get("positive_evidence", [])
    negatives = payload.get("negative_evidence", [])
    matched_positive = [_evidence_record(rule, alert) for rule in positives if rule_matches(rule, alert)]
    matched_negative = [_evidence_record(rule, alert) for rule in negatives if rule_matches(rule, alert)]
    raw_score = sum(float(value.get("weight", 0.0)) for value in matched_positive + matched_negative)
    positive_capacity = sum(max(0.0, float(rule.get("weight", 0.0))) for rule in positives)
    normalized_score = max(0.0, min(1.0, raw_score / max(positive_capacity, 0.001)))
    rejection_reasons = []
    if not required_passed:
        missing = [rule.get("reason") or rule.get("rule_id") for rule, matched in zip(required, required_matches) if not matched]
        rejection_reasons.append("Required evidence is missing: " + "; ".join(missing))
    if matched_exclusions:
        rejection_reasons.extend("Excluded: " + item["reason"] for item in matched_exclusions)
    return {
        "required_passed": required_passed,
        "excluded": bool(matched_exclusions),
        "valid": required_passed and not matched_exclusions,
        "raw_evidence_score": round(raw_score, 6),
        "evidence_score": round(normalized_score, 6),
        "supporting_evidence": matched_required + matched_positive,
        "contradictory_evidence": matched_negative + matched_exclusions,
        "rejection_reasons": rejection_reasons,
    }
