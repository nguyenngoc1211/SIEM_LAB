"""Parse the active Suricata ruleset into a deterministic SID catalog."""

from __future__ import annotations

import json
import logging
import re
import tarfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable


LOG = logging.getLogger(__name__)
HEADER_RE = re.compile(r"^(alert|drop|reject)\s+(\S+)\s+", re.IGNORECASE)
SID_RE = re.compile(r"(?:^|;)\s*sid\s*:\s*(\d+)\s*;", re.IGNORECASE)
REV_RE = re.compile(r"(?:^|;)\s*rev\s*:\s*(\d+)\s*;", re.IGNORECASE)
TACTIC_RE = re.compile(r"^TA\d{4}$")
TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")


@dataclass(frozen=True)
class MitreItem:
    id: str
    name: str | None = None


@dataclass(frozen=True)
class RuleRecord:
    sid: int
    rev: int
    action: str
    protocol: str
    signature: str
    rule_file: str
    enabled: bool
    source: str
    mitre: dict[str, list[MitreItem]] = field(default_factory=dict)

    def to_dict(self) -> dict:
        value = asdict(self)
        return value


@dataclass
class RuleCatalog:
    rules: dict[int, RuleRecord]
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        techniques = sorted({
            item.id
            for rule in self.rules.values()
            for item in rule.mitre.get("techniques", [])
        })
        mapped = sum(bool(rule.mitre.get("techniques")) for rule in self.rules.values())
        return {
            "schema_version": "1.0",
            "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "summary": {
                "active_rules": len(self.rules),
                "mitre_mapped_rules": mapped,
                "unique_sids": len(self.rules),
                "techniques": len(techniques),
            },
            "warnings": self.warnings,
            "rules": [self.rules[sid].to_dict() for sid in sorted(self.rules)],
        }

    def write(self, output: Path) -> None:
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("w", encoding="utf-8") as handle:
            json.dump(self.to_dict(), handle, ensure_ascii=False, indent=2)

    @classmethod
    def load(cls, path: Path) -> "RuleCatalog":
        with path.open(encoding="utf-8") as handle:
            payload = json.load(handle)
        rules: dict[int, RuleRecord] = {}
        for raw in payload.get("rules", []):
            mitre = {
                key: [MitreItem(**item) for item in raw.get("mitre", {}).get(key, [])]
                for key in ("tactics", "techniques")
            }
            rule = RuleRecord(
                sid=int(raw["sid"]), rev=int(raw.get("rev", 0)),
                action=str(raw["action"]), protocol=str(raw["protocol"]),
                signature=str(raw.get("signature", "")),
                rule_file=str(raw.get("rule_file", "unknown.rules")),
                enabled=bool(raw.get("enabled", True)),
                source=str(raw.get("source", "unknown")), mitre=mitre,
            )
            rules[rule.sid] = rule
        return cls(rules=rules, warnings=list(payload.get("warnings", [])))


def _logical_lines(lines: Iterable[str]) -> Iterable[str]:
    pending = ""
    for raw in lines:
        line = raw.rstrip("\r\n")
        if pending:
            line = pending + line.lstrip()
        if line.endswith("\\"):
            pending = line[:-1]
            continue
        yield line
        pending = ""
    if pending:
        yield pending


def _split_options(text: str) -> list[str]:
    parts: list[str] = []
    current: list[str] = []
    quoted = False
    escaped = False
    for char in text:
        if escaped:
            current.append(char)
            escaped = False
            continue
        if char == "\\":
            current.append(char)
            escaped = True
            continue
        if char == '"':
            quoted = not quoted
            current.append(char)
            continue
        if char == ";" and not quoted:
            part = "".join(current).strip()
            if part:
                parts.append(part)
            current = []
            continue
        current.append(char)
    tail = "".join(current).strip()
    if tail:
        parts.append(tail)
    return parts


def _option_map(rule: str) -> dict[str, list[str]]:
    start = rule.find("(")
    end = rule.rfind(")")
    if start < 0 or end <= start:
        return {}
    result: dict[str, list[str]] = {}
    for part in _split_options(rule[start + 1:end]):
        key, separator, value = part.partition(":")
        if not separator:
            continue
        result.setdefault(key.strip().lower(), []).append(value.strip())
    return result


def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] == '"':
        value = value[1:-1]
    return value.replace(r'\"', '"').replace(r"\\", "\\")


def _metadata(options: dict[str, list[str]]) -> dict[str, list[str]]:
    parsed: dict[str, list[str]] = {}
    for block in options.get("metadata", []):
        for item in block.split(","):
            key, separator, value = item.strip().partition(" ")
            if separator and value.strip():
                parsed.setdefault(key.lower(), []).append(value.strip())
    return parsed


def _mitre_items(metadata: dict[str, list[str]], kind: str,
                 sid: int, warnings: list[str]) -> list[MitreItem]:
    id_key = "mitre_tactic_id" if kind == "tactics" else "mitre_technique_id"
    name_key = "mitre_tactic_name" if kind == "tactics" else "mitre_technique_name"
    validator = TACTIC_RE if kind == "tactics" else TECHNIQUE_RE
    ids = metadata.get(id_key, [])
    names = metadata.get(name_key, [])
    if names and len(ids) != len(names):
        warnings.append(
            f"SID {sid}: malformed MITRE metadata: {len(ids)} {id_key} values but "
            f"{len(names)} {name_key} values"
        )
    result: list[MitreItem] = []
    for index, identifier in enumerate(ids):
        identifier = identifier.strip()
        if not validator.fullmatch(identifier):
            warnings.append(f"SID {sid}: malformed {id_key} value {identifier!r}")
            continue
        name = names[index].strip() if index < len(names) else None
        item = MitreItem(id=identifier, name=name or None)
        if item not in result:
            result.append(item)
    return result


def _source_for(sid: int, signature: str, origin: str | None) -> tuple[str, str | None]:
    if 1002001 <= sid <= 1002999 or signature.startswith("LAB "):
        return "custom", "a2.rules"
    if 1001001 <= sid <= 1001099 or signature.startswith("SOC LAB V2 "):
        return "custom", "local.rules"
    if origin:
        return "et", origin
    return "suricata_builtin", None


def parse_rule(line: str, *, default_file: str, origins: dict[int, str] | None = None,
               warnings: list[str] | None = None) -> RuleRecord | None:
    """Parse one enabled rule. Commented/unsupported lines return ``None``."""
    warnings = warnings if warnings is not None else []
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None
    header = HEADER_RE.match(stripped)
    if not header:
        return None
    sid_match = SID_RE.search(stripped)
    if not sid_match:
        warnings.append(f"{default_file}: enabled rule has no SID")
        return None
    sid = int(sid_match.group(1))
    rev_match = REV_RE.search(stripped)
    options = _option_map(stripped)
    signature = _unquote(options.get("msg", ['""'])[0])
    metadata = _metadata(options)
    mitre = {
        "tactics": _mitre_items(metadata, "tactics", sid, warnings),
        "techniques": _mitre_items(metadata, "techniques", sid, warnings),
    }
    source, rule_file = _source_for(sid, signature, (origins or {}).get(sid))
    return RuleRecord(
        sid=sid, rev=int(rev_match.group(1)) if rev_match else 0,
        action=header.group(1).lower(), protocol=header.group(2).lower(),
        signature=signature, rule_file=rule_file or default_file,
        enabled=True, source=source, mitre=mitre,
    )


def build_origin_map(archives: Iterable[Path]) -> tuple[dict[int, str], list[str]]:
    """Map SID to the original ET category filename without extracting archives."""
    origins: dict[int, str] = {}
    warnings: list[str] = []
    for archive in archives:
        try:
            with tarfile.open(archive, "r:*") as bundle:
                for member in bundle.getmembers():
                    if not member.isfile() or not member.name.endswith(".rules"):
                        continue
                    extracted = bundle.extractfile(member)
                    if extracted is None:
                        continue
                    for raw in extracted:
                        text = raw.decode("utf-8", errors="replace").lstrip()
                        if text.startswith("#"):
                            text = text[1:].lstrip()
                        sid_match = SID_RE.search(text)
                        if not sid_match:
                            continue
                        sid = int(sid_match.group(1))
                        filename = Path(member.name).name
                        previous = origins.get(sid)
                        if previous and previous != filename:
                            warnings.append(
                                f"SID {sid}: source archive duplicate in {previous} and {filename}"
                            )
                            continue
                        origins[sid] = filename
        except (OSError, tarfile.TarError) as error:
            warnings.append(f"Cannot read ET archive {archive}: {error}")
    return origins, warnings


def build_catalog(rule_paths: Iterable[Path], *, archives: Iterable[Path] = ()) -> RuleCatalog:
    origins, warnings = build_origin_map(archives)
    rules: dict[int, RuleRecord] = {}
    for path in rule_paths:
        try:
            with path.open(encoding="utf-8", errors="replace") as handle:
                for line in _logical_lines(handle):
                    record = parse_rule(
                        line, default_file=path.name, origins=origins, warnings=warnings,
                    )
                    if record is None:
                        continue
                    previous = rules.get(record.sid)
                    if previous:
                        warnings.append(
                            f"Duplicate active SID {record.sid}: {previous.rule_file} rev "
                            f"{previous.rev} and {record.rule_file} rev {record.rev}"
                        )
                        if record.rev <= previous.rev:
                            continue
                    rules[record.sid] = record
        except OSError as error:
            raise ValueError(f"Cannot read rule file {path}: {error}") from error
    for warning in warnings:
        LOG.warning(warning)
    return RuleCatalog(rules=rules, warnings=warnings)
