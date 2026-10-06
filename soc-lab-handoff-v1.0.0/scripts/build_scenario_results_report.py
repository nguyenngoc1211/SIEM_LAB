#!/usr/bin/env python3
"""Build one auditable Markdown report from the current A1/A2 JSON results."""

from __future__ import annotations

import json
import re
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = ROOT / "soc-attacker-advanced-v3.0.0" / "scenarios"
REPORTS = ROOT / "runtime" / "reports"
CODE_ROOT = ROOT.parents[0]
REPORTS_BUNDLE = CODE_ROOT / "reports" / "scenario-results-a1-a2"
OUTPUT = REPORTS_BUNDLE / "REPORT.md"
RERANKER_AUDIT = REPORTS / "reranker_audit.json"


def load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def yaml_scalar(text: str, key: str) -> str | None:
    match = re.search(rf"(?m)^[ \t]*{re.escape(key)}:[ \t]*(.+?)[ \t]*$", text)
    if not match:
        return None
    return match.group(1).strip().strip('"\'')


def load_definitions() -> tuple[dict[str, dict[str, Any]], dict[int, dict[str, Any]]]:
    by_id: dict[str, dict[str, Any]] = {}
    by_sid: dict[int, dict[str, Any]] = {}
    for group in ("a1", "a2"):
        for path in sorted((SCENARIOS / group).glob("**/scenario.yaml")):
            text = path.read_text(encoding="utf-8")
            scenario_id = yaml_scalar(text, "id") or path.parent.name
            sid_match = re.search(r"(?ms)^\s*expected_sid:\s*\n\s*-\s*(\d+)", text)
            item = {
                "id": scenario_id,
                "group": group.upper(),
                "name": yaml_scalar(text, "name"),
                "description": yaml_scalar(text, "description"),
                "rule_source": yaml_scalar(text, "rule_source"),
                "sid": int(sid_match.group(1)) if sid_match else None,
                "path": path.relative_to(ROOT).as_posix(),
            }
            by_id[scenario_id] = item
            if item["sid"] is not None:
                by_sid[item["sid"]] = item
    return by_id, by_sid


RULE_SOURCE_LABELS = {
    "et_open": "ET Open",
    "et": "ET Open",
    "owasp_crs": "OWASP CRS-derived",
    "custom": "Custom",
}


def rule_source_label(value: str | None, group: str) -> str:
    """Human-readable rule provenance, defaulting by scenario group."""
    if value:
        return RULE_SOURCE_LABELS.get(value, md(value))
    return "ET Open" if group == "A1" else "Custom"


def md(value: Any) -> str:
    if value is None or value == "":
        return "—"
    return str(value).replace("|", "&#124;").replace("\r", " ").replace("\n", " ")


def compact(value: str, limit: int = 360) -> str:
    value = " ".join(value.split())
    return value if len(value) <= limit else value[: limit - 1] + "…"


def code(value: str, limit: int = 360) -> str:
    return f"<code>{md(compact(value, limit))}</code>"


def attack_summary(report: dict[str, Any]) -> str:
    values: list[str] = []
    for action in report.get("traffic", {}).get("actions", []):
        path = str(action.get("path", ""))
        if "__soc_attack_marker__" in path or path == "/lab/auth/reset":
            continue
        command = action.get("attack_command")
        if not command and action.get("type") == "command":
            command = " ".join(str(item) for item in action.get("argv", []))
        if not command:
            action_type = action.get("type", "action")
            if action_type == "http":
                command = f"{action.get('method', 'HTTP')} {path}"
            elif action_type == "udp":
                command = (
                    f"UDP port={action.get('port')} count={action.get('count', 1)} "
                    f"payload_hex={action.get('payload_hex', '')}"
                )
            else:
                command = json.dumps(action, ensure_ascii=False, separators=(",", ":"))
        if command not in values:
            values.append(str(command))
    if not values:
        return "—"
    shown = [code(item, 260) for item in values[:2]]
    if len(values) > 2:
        shown.append(f"… ({len(values)} actions/payloads trong report)")
    return "<br>".join(shown)


def rule_summary(report: dict[str, Any], rules_by_sid: dict[int, dict[str, Any]]) -> str:
    expected = {int(item) for item in report.get("detection", {}).get("expected_sids", [])}
    rules = [
        item for item in report.get("suricata_rules_triggered", [])
        if not expected or int(item.get("sid", -1)) in expected
    ]
    if not rules:
        rules = [rules_by_sid[sid] for sid in sorted(expected) if sid in rules_by_sid]
    if not rules:
        return "Expected SID: " + md(", ".join(str(item) for item in sorted(expected)))
    rendered: list[str] = []
    for rule in rules:
        heading = (
            f"<strong>SID {rule.get('sid')}</strong> — {md(rule.get('signature'))} "
            f"(<code>{md(rule.get('rule_file'))}</code>, source={md(rule.get('source'))})"
        )
        raw = rule.get("raw_rule")
        rendered.append(heading + ("<br>" + code(str(raw), 4000) if raw else ""))
    return "<br>".join(rendered)


def technique_candidates(report: dict[str, Any]) -> list[tuple[str, float]]:
    scores: dict[str, float] = {}
    for output in report.get("mapper_output", []):
        candidates: list[dict[str, Any]] = []
        primary = output.get("primary_mapping")
        if isinstance(primary, dict):
            candidates.append(primary)
        candidates.extend(item for item in output.get("mappings", []) if isinstance(item, dict))
        candidates.extend(
            item for item in output.get("alternative_candidates", []) if isinstance(item, dict)
        )
        for item in candidates:
            technique = item.get("technique_id")
            confidence = item.get("confidence")
            if not technique or confidence is None:
                continue
            scores[str(technique)] = max(scores.get(str(technique), 0.0), float(confidence))
    return sorted(scores.items(), key=lambda item: (-item[1], item[0]))


def top_three(report: dict[str, Any]) -> str:
    candidates = technique_candidates(report)[:3]
    values = [f"{index}. <code>{md(technique)}</code> = {confidence:.6f}" for index, (technique, confidence) in enumerate(candidates, 1)]
    values.extend(f"{index}. —" for index in range(len(values) + 1, 4))
    return "<br>".join(values)


def definition_state(
    report: dict[str, Any], definitions: dict[str, dict[str, Any]], definitions_by_sid: dict[int, dict[str, Any]],
) -> str:
    scenario_id = str(report.get("scenario_id", ""))
    expected = [int(item) for item in report.get("detection", {}).get("expected_sids", [])]
    expected_sid = expected[0] if expected else None
    current = definitions.get(scenario_id)
    if scenario_id.startswith("SCN-"):
        return "legacy (YAML còn lưu)" if current else "legacy (chỉ còn report)"
    if current and current.get("sid") == expected_sid:
        return "hiện hành"
    if current:
        return f"lịch sử; ID hiện dùng SID {current.get('sid')}"
    same_sid = definitions_by_sid.get(expected_sid) if expected_sid is not None else None
    if same_sid:
        return f"lịch sử; SID hiện thuộc {same_sid['id']}"
    return "lịch sử; chỉ còn report"


def behavior(report: dict[str, Any], definitions_by_sid: dict[int, dict[str, Any]]) -> str:
    name = str(report.get("scenario_name") or report.get("scenario_id") or "Không có tên")
    expected = report.get("detection", {}).get("expected_sids", [])
    definition = definitions_by_sid.get(int(expected[0])) if expected else None
    description = definition.get("description") if definition else None
    if description and description.lower() not in name.lower():
        return md(f"{name} — {description}")
    return md(name)


def load_reports_from(base: Path) -> list[tuple[str, Path, dict[str, Any]]]:
    values: list[tuple[str, Path, dict[str, Any]]] = []
    for group in ("a1", "a2"):
        for path in sorted((base / group).glob("*.json")):
            report = load_json(path)
            if isinstance(report, dict) and report.get("scenario_id"):
                values.append((group.upper(), path, report))
    return values


def load_reports() -> list[tuple[str, Path, dict[str, Any]]]:
    return load_reports_from(REPORTS)


def expected_techniques(report: dict[str, Any]) -> list[str]:
    values = report.get("ground_truth", {}).get("technique_ids", [])
    return list(values or report.get("mitre", {}).get("expected_techniques", []))


def count_status(items: list[dict[str, Any]], section: str, expected: str = "PASS") -> int:
    return sum(item.get(section, {}).get("status") == expected for item in items)


def exact_mapping(report: dict[str, Any]) -> bool:
    expected = set(expected_techniques(report))
    observed = set(report.get("mitre", {}).get("observed_techniques", []))
    return bool(expected) and expected == observed


def candidate_hit(report: dict[str, Any], depth: int) -> bool:
    expected = set(expected_techniques(report))
    candidates = {item[0] for item in technique_candidates(report)[:depth]}
    return bool(expected) and bool(expected & candidates)


def report_ids(items: list[dict[str, Any]]) -> str:
    return ", ".join(f"`{item.get('scenario_id')}`" for item in items) or "không có"


def technique_summary(items: list[dict[str, Any]]) -> list[str]:
    techniques = sorted({value for item in items for value in expected_techniques(item)})
    rows = [
        "| Technique dự kiến | Scenario | Exact primary | Expected top 3 | Mapping MISSING |",
        "|---|---:|---:|---:|---:|",
    ]
    for technique in techniques:
        matching = [item for item in items if technique in expected_techniques(item)]
        rows.append(
            f"| `{technique}` | {len(matching)} | "
            f"{sum(exact_mapping(item) for item in matching)}/{len(matching)} | "
            f"{sum(candidate_hit(item, 3) for item in matching)}/{len(matching)} | "
            f"{sum(item.get('mitre', {}).get('status') == 'MISSING' for item in matching)}/{len(matching)} |"
        )
    return rows


def rule_source_cell(
    report: dict[str, Any], definitions_by_sid: dict[int, dict[str, Any]], group: str,
) -> str:
    expected = report.get("detection", {}).get("expected_sids", [])
    definition = definitions_by_sid.get(int(expected[0])) if expected else None
    value = definition.get("rule_source") if definition else None
    return rule_source_label(value, group)


def table_rows(
    group: str, reports: list[tuple[str, Path, dict[str, Any]]], definitions: dict[str, dict[str, Any]],
    definitions_by_sid: dict[int, dict[str, Any]], rules_by_sid: dict[int, dict[str, Any]],
) -> list[str]:
    rows = [
        "| Kịch bản | Trạng thái artifact | Mô tả nhanh hành vi | Command / payload tấn công | Rule dự kiến kích hoạt (đã đối chiếu alert thực tế) | Rule source | Technique dự kiến | Technique thực tế | Confidence top 3 | Detection / Wazuh / Mapping / Overall |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for item_group, path, report in reports:
        if item_group != group:
            continue
        expected = expected_techniques(report)
        observed = report.get("mitre", {}).get("observed_techniques", [])
        outcomes = (
            f"{md(report.get('detection', {}).get('status'))} / "
            f"{md(report.get('siem', {}).get('status'))} / "
            f"{md(report.get('mitre', {}).get('status'))} / "
            f"<strong>{md(report.get('result'))}</strong>"
        )
        scenario = (
            f"<strong>{md(report.get('scenario_id'))}</strong><br>"
            f"{md(report.get('scenario_name'))}<br>"
            f"<code>{md(path.relative_to(ROOT).as_posix())}</code>"
        )
        rows.append(
            "| " + " | ".join([
                scenario,
                md(definition_state(report, definitions, definitions_by_sid)),
                behavior(report, definitions_by_sid),
                attack_summary(report),
                rule_summary(report, rules_by_sid),
                rule_source_cell(report, definitions_by_sid, group),
                "<br>".join(f"<code>{md(item)}</code>" for item in expected) or "—",
                "<br>".join(f"<code>{md(item)}</code>" for item in observed) or "—",
                top_three(report),
                outcomes,
            ]) + " |"
        )
    return rows


def rule_source_summary(definitions: dict[str, dict[str, Any]]) -> list[str]:
    rows = [
        "| Nhóm | ET Open | OWASP CRS-derived | Custom | Tổng | Có nguồn tham khảo |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    order = ("ET Open", "OWASP CRS-derived", "Custom")

    def ratio(sourced: int, total: int) -> str:
        if not total:
            return f"{sourced}/{total}"
        return f"{sourced}/{total} ({100 * sourced / total:.1f}%)"

    totals: Counter[str] = Counter()
    for group in ("A1", "A2"):
        items = [item for item in definitions.values() if item.get("group") == group]
        counts = Counter(rule_source_label(item.get("rule_source"), group) for item in items)
        totals.update(counts)
        total = len(items)
        sourced = counts["ET Open"] + counts["OWASP CRS-derived"]
        rows.append(
            f"| {group} | " + " | ".join(str(counts[label]) for label in order)
            + f" | {total} | {ratio(sourced, total)} |"
        )
    grand = sum(totals.values())
    grand_sourced = totals["ET Open"] + totals["OWASP CRS-derived"]
    rows.append(
        "| Tổng | " + " | ".join(str(totals[label]) for label in order)
        + f" | {grand} | {ratio(grand_sourced, grand)} |"
    )
    return rows


def build() -> str:
    definitions, definitions_by_sid = load_definitions()
    reports = load_reports()
    audit = load_json(RERANKER_AUDIT) if RERANKER_AUDIT.exists() else {}
    audit_summary = audit.get("summary", {}) if isinstance(audit, dict) else {}
    rules_by_sid: dict[int, dict[str, Any]] = {}
    for _, _, report in reports:
        for rule in report.get("suricata_rules_triggered", []):
            if rule.get("sid") is not None:
                rules_by_sid[int(rule["sid"])] = rule
    grouped = {
        group: [report for item_group, _, report in reports if item_group == group]
        for group in ("A1", "A2")
    }
    standard = [report for _, _, report in reports if str(report.get("scenario_id", "")).startswith(("A1-", "A2-"))]
    legacy = [report for _, _, report in reports if report not in standard]

    generated_at = datetime.now().astimezone().isoformat(timespec="seconds")
    definition_ids = set(definitions)
    report_id_set = {str(item.get("scenario_id")) for item in standard}
    previous_standard: list[dict[str, Any]] = []
    previous_location: Path | None = None
    archive_root = REPORTS / "archive"
    if archive_root.exists():
        for archive_dir in sorted(
            (path for path in archive_root.iterdir() if path.is_dir()),
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        ):
            archived = load_reports_from(archive_dir)
            archived_standard = [
                report for _, _, report in archived
                if str(report.get("scenario_id", "")).startswith(("A1-", "A2-"))
            ]
            archived_ids = {str(item.get("scenario_id")) for item in archived_standard}
            if archived_ids == definition_ids:
                previous_standard = archived_standard
                previous_location = archive_dir
                break
    missing_reports = sorted(definition_ids - report_id_set)
    unexpected_reports = sorted(report_id_set - definition_ids)
    detection_failures = [item for item in standard if item.get("detection", {}).get("status") != "PASS"]
    ingestion_failures = [item for item in standard if item.get("siem", {}).get("status") != "PASS"]
    mapping_failures = [item for item in standard if item.get("mitre", {}).get("status") != "PASS"]
    mapping_missing = [item for item in standard if item.get("mitre", {}).get("status") == "MISSING"]
    top3_recoveries = [item for item in standard if not exact_mapping(item) and candidate_hit(item, 3)]
    failed_expected = Counter(
        technique
        for item in mapping_failures
        for technique in expected_techniques(item)
    )
    mapper_statuses = Counter(
        str(output.get("mapping_status", "unknown"))
        for item in standard
        for output in item.get("mapper_output", [])
        if isinstance(output, dict)
    )
    normalizer_versions = Counter(
        str(output.get("normalized_alert", {}).get("derived", {}).get("renderer_version", "unknown"))
        for item in standard
        for output in item.get("mapper_output", [])
        if isinstance(output, dict)
    )

    mapper_status_text = ", ".join(f"`{key}`={value}" for key, value in sorted(mapper_statuses.items())) or "không có output"
    normalizer_text = ", ".join(f"`{key}`={value}" for key, value in sorted(normalizer_versions.items())) or "không xác định"
    flow_normalizer = ", ".join(sorted(normalizer_versions)) or "không xác định"
    failed_technique_text = ", ".join(
        f"`{technique}` ({count})" for technique, count in failed_expected.most_common()
    ) or "không có"
    detection_note = (
        f"Detection/ingestion không thành công ở: {report_ids(detection_failures)}. "
        "Các scenario này không có alert hợp lệ để gọi mapper."
        if detection_failures
        else "Không còn scenario nào thiếu Suricata/Wazuh alert."
    )
    comparison_note = ""
    if previous_standard and previous_location is not None:
        previous_grouped = {
            group: [
                item for item in previous_standard
                if str(item.get("scenario_id", "")).startswith(group + "-")
            ]
            for group in ("A1", "A2")
        }
        current_exact = sum(exact_mapping(item) for item in standard)
        previous_exact = sum(exact_mapping(item) for item in previous_standard)
        current_top3 = sum(candidate_hit(item, 3) for item in standard)
        previous_top3 = sum(candidate_hit(item, 3) for item in previous_standard)
        previous_missing = sum(
            item.get("mitre", {}).get("status") == "MISSING" for item in previous_standard
        )
        current_group_exact = {
            group: sum(exact_mapping(item) for item in grouped[group]) for group in ("A1", "A2")
        }
        previous_group_exact = {
            group: sum(exact_mapping(item) for item in previous_grouped[group]) for group in ("A1", "A2")
        }
        comparison_note = (
            f"- So với snapshot ngay trước lần chạy tại `{previous_location.relative_to(ROOT).as_posix()}`: "
            f"exact primary thay đổi từ **{previous_exact}/90** thành **{current_exact}/90** "
            f"(**{current_exact - previous_exact:+d}**), expected trong top 3 tăng từ "
            f"**{previous_top3}/90** thành **{current_top3}/90** "
            f"(**{current_top3 - previous_top3:+d}**). A1 exact thay đổi "
            f"{previous_group_exact['A1']}/15 → {current_group_exact['A1']}/15 "
            f"({current_group_exact['A1'] - previous_group_exact['A1']:+d}), A2 thay đổi "
            f"{previous_group_exact['A2']}/75 → {current_group_exact['A2']}/75 "
            f"({current_group_exact['A2'] - previous_group_exact['A2']:+d}). Số kết quả `MISSING` "
            f"thay đổi từ {previous_missing} thành {len(mapping_missing)}."
        )

    reranker_audit_notes: list[str] = []
    if audit_summary:
        scenario_count = int(audit_summary.get("scenario_count", 0))
        final_limit = int(audit.get("expected_limit", 0))
        top3_gains = audit_summary.get("top3_gains", [])
        expected_not_in_pool = audit_summary.get("expected_not_in_final_pool", [])
        expected_backfilled = audit_summary.get("expected_backfilled_scenario_ids", [])
        rank_movements = audit_summary.get("expected_rank_movements", {})
        comparable_ranks = sum(
            int(rank_movements.get(key, 0)) for key in ("improved", "worsened", "unchanged")
        )
        reranker_audit_notes = [
            (
                f"- Kiểm toán cấu hình mới: công thức reranker đúng ở "
                f"**{audit_summary.get('formula_ok_scenarios', 0)}/{scenario_count}** scenario; "
                f"metadata công thức và `final_candidate_limit={final_limit}` đúng ở "
                f"**{audit_summary.get('pipeline_limit_ok', 0)}/{scenario_count}** scenario; "
                f"mọi final pool đều không quá {final_limit} phần tử. Số candidate invalid lọt vào final pool: "
                f"**{audit_summary.get('invalid_selected_candidates', 0)}**."
            ),
            (
                f"- Hiệu quả top {final_limit}/backfill: expected technique xuất hiện trong trace **{audit_summary.get('expected_in_trace', 0)}/{scenario_count}** "
                f"và nằm trong final valid pool **{audit_summary.get('expected_in_final_pool', 0)}/{scenario_count}**. "
                f"Backfill được sử dụng ở **{audit_summary.get('backfill_used_scenarios', 0)}** scenario và giữ lại expected candidate có reranker rank > {final_limit} ở "
                f"**{len(expected_backfilled)}** case: {', '.join(f'`{item}`' for item in expected_backfilled) or 'không có'}. "
                f"So với snapshot trước, số case expected vào top 3 thay đổi **{len(top3_gains)}** case theo hướng có lợi. "
                f"Còn **{len(expected_not_in_pool)}** case expected bị rule/evidence loại khỏi final pool: "
                f"{', '.join(f'`{item}`' for item in expected_not_in_pool) or 'không có'}."
            ),
            (
                f"- Tác động của thang điểm: trên **{comparable_ranks}** case có expected candidate so sánh được, rank không đổi ở "
                f"**{rank_movements.get('unchanged', 0)}/{comparable_ranks}**; median reranker score thay đổi từ "
                f"**{audit_summary.get('expected_reranker_component_median_before', 0):.6f}** thành "
                f"**{audit_summary.get('expected_reranker_component_median_after', 0):.6f}**; median candidate score thay đổi từ "
                f"**{audit_summary.get('expected_candidate_score_median_before', 0):.6f}** thành "
                f"**{audit_summary.get('expected_candidate_score_median_after', 0):.6f}**. Vì threshold vẫn là `0.55`, "
                f"`MISSING` thay đổi **{audit_summary.get('missing_before', 0)} → {audit_summary.get('missing_after', 0)}** và exact primary "
                f"thay đổi **{audit_summary.get('exact_before', 0)}/90 → {audit_summary.get('exact_after', 0)}/90**."
            ),
            (
                f"- Chi tiết audit có thể tái tạo nằm tại `{RERANKER_AUDIT.relative_to(ROOT).as_posix()}`; "
                "file này lưu kết quả kiểm tra công thức, final pool và so sánh từng scenario với baseline."
            ),
        ]

    lines = [
        "# Thống kê chi tiết toàn bộ kịch bản A1 và A2",
        "",
        f"Thời điểm sinh báo cáo: `{generated_at}`.",
        "",
        f"> Bundle: `{REPORTS_BUNDLE.relative_to(CODE_ROOT).as_posix()}`. "
        "Mọi đường dẫn tương đối trong báo cáo tính từ gốc `soc-lab-handoff-v1.0.0/`; "
        "artifact thô nằm ở `runtime/reports/a1|a2/` và không được commit vào git.",
        "",
        "## Phạm vi và cách đọc",
        "",
        f"Báo cáo được sinh trực tiếp từ **{len(standard)} kết quả của lần chạy mới nhất** trong `runtime/reports/a1/` và `runtime/reports/a2/`, rồi đối chiếu với {len(definitions)} YAML hiện hành trong `scenarios/a1/` và `scenarios/a2/`. Kết quả cũ đã được tách khỏi tập đo hiện tại và lưu dưới `runtime/reports/archive/`.",
        "",
        "Mỗi scenario tạo traffic, chờ Wazuh ingest, chọn đúng **một alert gần `traffic_finished_at` nhất**, rồi gửi alert đó tới production webhook n8n. Workflow n8n chuẩn hóa alert và trả thẳng kết quả mapping đầy đủ; runner không gửi Technique ID dự kiến vào mapper. Vì vậy A1 và A2 trong báo cáo này là cùng một phép đo end-to-end và có thể so sánh trực tiếp.",
        "",
        "`Technique thực tế` là `primary_mapping.technique_id` do n8n trả về và runner ghi vào `mitre.observed_techniques`. `Confidence top 3` được lấy từ primary cộng với `alternative_candidates`, sắp theo confidence giảm dần. `Exact TechID` chỉ PASS khi tập technique thực tế bằng đúng tập technique dự kiến; không tính quan hệ cha/con là exact.",
        "",
        f"Độ đầy đủ artifact: thiếu report cho YAML hiện hành: **{len(missing_reports)}** ({md(', '.join(missing_reports) or 'không có')}); report không còn YAML tương ứng: **{len(unexpected_reports)}** ({md(', '.join(unexpected_reports) or 'không có')}); legacy: **{len(legacy)}**.",
        "",
        "## Tóm tắt định lượng",
        "",
        "| Nhóm | Report chuẩn | Detection PASS | Wazuh PASS | Exact TechID | Overall PASS | Expected ở top 1 | Expected trong top 3 |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for group in ("A1", "A2"):
        items = [item for item in grouped[group] if str(item.get("scenario_id", "")).startswith(group + "-")]
        lines.append(
            f"| {group} | {len(items)} | {count_status(items, 'detection')}/{len(items)} | "
            f"{count_status(items, 'siem')}/{len(items)} | {sum(exact_mapping(item) for item in items)}/{len(items)} | "
            f"{sum(item.get('result') == 'PASS' for item in items)}/{len(items)} | "
            f"{sum(candidate_hit(item, 1) for item in items)}/{len(items)} | "
            f"{sum(candidate_hit(item, 3) for item in items)}/{len(items)} |"
        )
    lines.append(
        f"| Tổng | {len(standard)} | {count_status(standard, 'detection')}/{len(standard)} | "
        f"{count_status(standard, 'siem')}/{len(standard)} | {sum(exact_mapping(item) for item in standard)}/{len(standard)} | "
        f"{sum(item.get('result') == 'PASS' for item in standard)}/{len(standard)} | "
        f"{sum(candidate_hit(item, 1) for item in standard)}/{len(standard)} | "
        f"{sum(candidate_hit(item, 3) for item in standard)}/{len(standard)} |"
    )
    lines.extend([
        "",
        "## Nguồn gốc rule theo nhóm kịch bản",
        "",
    ])
    lines.extend(rule_source_summary(definitions))
    lines.extend([
        "",
        "## Nhận xét",
        "",
        f"- Traffic/Suricata/Wazuh: detection PASS **{count_status(standard, 'detection')}/{len(standard)}**, ingestion PASS **{count_status(standard, 'siem')}/{len(standard)}**. {detection_note}",
        f"- Mapping end-to-end: exact primary **{sum(exact_mapping(item) for item in standard)}/{len(standard)}**; technique dự kiến xuất hiện trong top 3 **{sum(candidate_hit(item, 3) for item in standard)}/{len(standard)}**. Có **{len(top3_recoveries)}** trường hợp primary sai nhưng expected technique vẫn nằm trong top 3: {report_ids(top3_recoveries)}.",
        *([comparison_note] if comparison_note else []),
        *reranker_audit_notes,
        f"- Có **{len(mapping_failures)}** scenario mapping không PASS, trong đó **{len(mapping_missing)}** là `MISSING`: {report_ids(mapping_missing)}. Các technique dự kiến xuất hiện nhiều trong nhóm mapping lỗi: {failed_technique_text}.",
        f"- Trạng thái raw do workflow n8n trả về: {mapper_status_text}. Phiên bản normalizer ghi trong output: {normalizer_text}. Các con số này được đọc từ `mapper_output`, không suy diễn từ expected TechID.",
        "- Việc bỏ đường tắt metadata Technique ID của rule làm lộ rõ chất lượng semantic mapping thực tế: nhiều alert vẫn được Suricata/Wazuh phát hiện đúng nhưng mapper chọn technique khác hoặc không đủ ngưỡng. Đây là kết quả đo hợp lệ của pipeline hiện tại, không nên đổi expected để làm đẹp tỷ lệ PASS.",
        "- Cột command/payload chỉ bỏ các marker phân đoạn và request reset trạng thái. Với burst nhiều request, bảng hiển thị hai action đầu và tổng số action để giữ báo cáo có thể đọc được; JSON gốc vẫn chứa toàn bộ lệnh.",
        "",
        "## Phân tích theo technique dự kiến",
        "",
    ])
    lines.extend(technique_summary(standard))
    lines.extend([
        "",
        "## Chi tiết A1",
        "",
    ])
    lines.extend(table_rows("A1", reports, definitions, definitions_by_sid, rules_by_sid))
    lines.extend(["", "## Chi tiết A2", ""])
    lines.extend(table_rows("A2", reports, definitions, definitions_by_sid, rules_by_sid))
    lines.extend([
        "",
        "## Sơ đồ cấu trúc scenario của dự án",
        "",
        "```text",
        "soc-lab-handoff-v1.0.0/",
        "├── soc-attacker-advanced-v3.0.0/",
        "│   ├── scenarios/",
        "│   │   ├── a1/<Technique>/<Scenario>/scenario.yaml   # Định nghĩa A1 dùng rule ET Open",
        "│   │   ├── a2/<Technique>/<Scenario>/scenario.yaml   # Định nghĩa A2 custom",
        "│   │   │   └── rule.rules                            # Bản rule riêng của từng A2",
        "│   │   ├── a2/catalog.json                           # Catalog sinh A2",
        "│   │   └── catalog.json                              # Catalog scenario/legacy cấp chung",
        "│   ├── src/",
        "│   │   ├── a1_runner.py                              # CLI nhóm A1",
        "│   │   ├── a2_runner.py                              # CLI nhóm A2",
        "│   │   └── soc_scenarios/                            # Runner, evaluator, parser EVE/Wazuh, mapper client",
        "│   ├── tests/test_scenario_framework.py              # Unit tests framework dùng chung",
        "│   └── data/rule_catalog.json                        # Catalog active rule do build_rule_catalog tạo",
        "├── sensor/",
        "│   ├── local.rules                                   # Custom rules thế hệ scenario cũ/A1 lab",
        "│   ├── a2.rules                                      # 75 rule A2, SID 1002001–1002075",
        "│   └── entrypoint.sh                                  # Ghép ET Open + custom rules thành ruleset runtime",
        "├── runtime/",
        "│   ├── reports/",
        "│   │   ├── a1/<Scenario>.json                        # Kết quả chi tiết từng A1",
        "│   │   ├── a2/<Scenario>.json                        # Kết quả chi tiết từng A2",
        "│   │   ├── archive/<mốc-chạy>/a1|a2/                # Snapshot report cũ, không tính vào lần đo hiện tại",
        "│   │   └── mitre_coverage.json                       # Tổng hợp coverage khác của framework",
        "│   ├── ground-truth/",
        "│   │   ├── a1-scenario-runs.jsonl                    # Lịch sử lần chạy A1",
        "│   │   └── a2-scenario-runs.jsonl                    # Lịch sử lần chạy A2",
        "│   └── suricata-logs/eve.json                        # EVE event/alert gốc từ Suricata",
        "├── docs/",
        "│   └── A2_RUN_ISSUES.md                              # Nhật ký chạy và sửa lỗi A2",
        "└── docker-compose.yml                                # Mount log/rule state và nối các container",
        "```",
        "",
        "### Dòng dữ liệu khi chạy",
        "",
        "```text",
        "scenario.yaml -> a1_runner.py / a2_runner.py -> traffic từ soc_attacker_v2",
        "              -> Suricata active rules -> runtime/suricata-logs/eve.json",
        "              -> Wazuh alerts.json (Docker volume, mount read-only vào attacker)",
        "              -> chọn alert gần traffic_finished_at nhất",
        f"              -> production webhook n8n -> normalizer {flow_normalizer} -> MITRE mapper",
        "              -> runtime/reports/a1|a2/<Scenario>.json",
        "              -> runtime/ground-truth/a1|a2-scenario-runs.jsonl",
        "```",
        "",
        "Rule A1 đến từ ET Open và được giữ trong ruleset runtime của volume Suricata; mỗi YAML A1 tham chiếu SID chứ không sao chép rule vào thư mục scenario. Rule A2 có cả bản tổng hợp `sensor/a2.rules` và bản cạnh từng scenario để audit. Wazuh alert gốc nằm trong Docker volume tại `/var/ossec/logs/alerts/alerts.json`, được container attacker đọc qua `/var/ossec-logs/alerts/alerts.json`. Mỗi JSON report lưu toàn bộ `attack_commands`, các Wazuh alert thu được, `selected_wazuh_alert`, thông tin tương quan alert và response n8n đầy đủ trong `mapper_output` (gồm cả `candidate_trace` khi workflow trả trường này).",
        "",
        "## Tái tạo báo cáo",
        "",
        "```powershell",
        "python scripts\\build_scenario_results_report.py",
        "```",
    ])
    return "\n".join(lines) + "\n"


def main() -> None:
    OUTPUT.write_text(build(), encoding="utf-8", newline="\n")
    print(f"Wrote {OUTPUT}")


if __name__ == "__main__":
    main()
