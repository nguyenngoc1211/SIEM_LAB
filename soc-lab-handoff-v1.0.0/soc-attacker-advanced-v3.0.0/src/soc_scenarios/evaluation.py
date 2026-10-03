"""Evaluate environment, traffic, detection, ingestion, and MITRE independently."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from .eve import AlertObservation
from .scenario_model import Scenario
from .siem import SIEMAlert


PASS = "PASS"
FAIL = "FAIL"
MISSING = "MISSING"
NOT_TESTED = "NOT_TESTED"


@dataclass(frozen=True)
class EvaluationResult:
    environment_status: str
    traffic_status: str
    detection_status: str
    ingestion_status: str
    mapping_status: str
    result: str
    expected_sids: tuple[int, ...]
    observed_sids: tuple[int, ...]
    unexpected_sids: tuple[int, ...]
    observed_tactics: tuple[str, ...]
    observed_techniques: tuple[str, ...]
    mapping_sources: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def evaluate(
    scenario: Scenario, *, environment_ok: bool, traffic_ok: bool,
    eve_alerts: list[AlertObservation], siem_alerts: list[SIEMAlert],
    mapper_techniques: set[str] | None = None,
    mapper_statuses: set[str] | None = None,
    mapper_source: str = "MITRE_MAPPER_API",
) -> EvaluationResult:
    expected = set(scenario.expected_sids)
    observed = {alert.signature_id for alert in eve_alerts}
    expected_observed = observed & expected
    detection_ok = (
        expected.issubset(observed)
        and sum(alert.signature_id in expected for alert in eve_alerts)
        >= scenario.expected.minimum_alerts
    )
    siem_sids = {alert.signature_id for alert in siem_alerts if alert.signature_id is not None}
    ingestion_ok = expected.issubset(siem_sids)
    expected_siem_alerts = [
        alert for alert in siem_alerts if alert.signature_id in expected
    ]
    observed_tactics = {value for alert in expected_siem_alerts for value in alert.tactics}
    observed_techniques = (
        set(mapper_techniques) if mapper_techniques is not None else
        {value for alert in expected_siem_alerts for value in alert.techniques}
    )
    expected_tactics = set(scenario.mitre.tactic_ids)
    expected_techniques = set(scenario.mitre.technique_ids)

    environment_status = PASS if environment_ok else FAIL
    traffic_status = PASS if traffic_ok else FAIL
    detection_status = PASS if detection_ok else FAIL
    if not scenario.expected.ingestion_required:
        ingestion_status = NOT_TESTED
    else:
        ingestion_status = PASS if ingestion_ok else FAIL
    if not scenario.expected.mapping_required:
        mapping_status = NOT_TESTED
    elif not expected_siem_alerts:
        mapping_status = MISSING
    elif mapper_statuses is not None:
        if not mapper_statuses:
            mapping_status = MISSING
        elif scenario.expected.mapping_status != "mapped":
            mapping_status = (
                PASS if mapper_statuses == {scenario.expected.mapping_status} else FAIL
            )
        elif not observed_techniques:
            mapping_status = MISSING
        else:
            mapping_status = PASS if expected_techniques == observed_techniques else FAIL
    elif not observed_techniques:
        mapping_status = MISSING
    else:
        mapping_status = (
            PASS if expected_techniques == observed_techniques
            and expected_tactics == observed_tactics else FAIL
        )
    required = [environment_status, traffic_status, detection_status]
    if scenario.expected.ingestion_required:
        required.append(ingestion_status)
    if scenario.expected.mapping_required:
        required.append(mapping_status)
    return EvaluationResult(
        environment_status=environment_status, traffic_status=traffic_status,
        detection_status=detection_status, ingestion_status=ingestion_status,
        mapping_status=mapping_status, result=PASS if all(item == PASS for item in required) else FAIL,
        expected_sids=tuple(sorted(expected)), observed_sids=tuple(sorted(expected_observed)),
        unexpected_sids=tuple(sorted(observed - expected)),
        observed_tactics=tuple(sorted(observed_tactics)),
        observed_techniques=tuple(sorted(observed_techniques)),
        mapping_sources=(
            (mapper_source,) if mapper_statuses is not None else
            tuple(sorted({alert.mapping_source for alert in expected_siem_alerts}))
        ),
    )
