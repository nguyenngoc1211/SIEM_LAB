"""Small dependency-free YAML subset loader for scenario manifests.

Supported constructs are intentionally limited to indented mappings, scalar
lists, and scalar values. This keeps the isolated attacker image offline while
still accepting the documented scenario schema.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


class YamlError(ValueError):
    pass


def _strip_comment(text: str) -> str:
    quoted: str | None = None
    escaped = False
    for index, char in enumerate(text):
        if escaped:
            escaped = False
            continue
        if char == "\\" and quoted == '"':
            escaped = True
            continue
        if char in {'"', "'"}:
            quoted = None if quoted == char else (char if quoted is None else quoted)
            continue
        if char == "#" and quoted is None and (index == 0 or text[index - 1].isspace()):
            return text[:index].rstrip()
    return text.rstrip()


def _scalar(value: str) -> Any:
    value = value.strip()
    if not value:
        return None
    if value.startswith('"') and value.endswith('"'):
        try:
            return json.loads(value)
        except json.JSONDecodeError as error:
            raise YamlError(f"invalid quoted scalar {value!r}: {error}") from error
    if value.startswith("'") and value.endswith("'"):
        return value[1:-1].replace("''", "'")
    lowered = value.lower()
    if lowered in {"true", "false"}:
        return lowered == "true"
    if lowered in {"null", "~"}:
        return None
    if value.startswith("[") or value.startswith("{"):
        try:
            return json.loads(value)
        except json.JSONDecodeError as error:
            raise YamlError(f"inline collections must use JSON syntax: {error}") from error
    if re.fullmatch(r"-?\d+", value):
        return int(value)
    if re.fullmatch(r"-?(?:\d+\.\d*|\d*\.\d+)", value):
        return float(value)
    return value


def loads(text: str) -> dict[str, Any]:
    tokens: list[tuple[int, str, int]] = []
    for line_number, raw in enumerate(text.splitlines(), 1):
        if "\t" in raw[:len(raw) - len(raw.lstrip())]:
            raise YamlError(f"line {line_number}: tabs are not allowed for indentation")
        cleaned = _strip_comment(raw)
        if not cleaned.strip() or cleaned.lstrip().startswith("---"):
            continue
        indent = len(cleaned) - len(cleaned.lstrip(" "))
        tokens.append((indent, cleaned.strip(), line_number))
    if not tokens:
        raise YamlError("empty YAML document")

    def parse_node(index: int, indent: int) -> tuple[Any, int]:
        if index >= len(tokens) or tokens[index][0] != indent:
            line = tokens[index][2] if index < len(tokens) else "EOF"
            raise YamlError(f"line {line}: inconsistent indentation")
        is_list = tokens[index][1].startswith("- ") or tokens[index][1] == "-"
        container: Any = [] if is_list else {}
        while index < len(tokens):
            current_indent, content, line_number = tokens[index]
            if current_indent < indent:
                break
            if current_indent > indent:
                raise YamlError(f"line {line_number}: unexpected indentation")
            current_is_list = content.startswith("- ") or content == "-"
            if current_is_list != is_list:
                raise YamlError(f"line {line_number}: cannot mix list and mapping entries")
            if is_list:
                item = content[1:].strip()
                if not item:
                    if index + 1 >= len(tokens) or tokens[index + 1][0] <= indent:
                        raise YamlError(f"line {line_number}: empty list item")
                    value, index = parse_node(index + 1, tokens[index + 1][0])
                    container.append(value)
                    continue
                if ":" in item:
                    raise YamlError(
                        f"line {line_number}: list mappings are outside the supported scenario subset"
                    )
                container.append(_scalar(item))
                index += 1
                continue
            key, separator, value_text = content.partition(":")
            if not separator or not key.strip():
                raise YamlError(f"line {line_number}: expected 'key: value'")
            key = key.strip()
            if key in container:
                raise YamlError(f"line {line_number}: duplicate key {key!r}")
            if value_text.strip():
                container[key] = _scalar(value_text)
                index += 1
                continue
            if index + 1 >= len(tokens) or tokens[index + 1][0] <= indent:
                container[key] = None
                index += 1
                continue
            value, index = parse_node(index + 1, tokens[index + 1][0])
            container[key] = value
        return container, index

    root_indent = tokens[0][0]
    value, end = parse_node(0, root_indent)
    if end != len(tokens) or not isinstance(value, dict):
        raise YamlError("scenario YAML root must be a mapping")
    return value


def load(path: Path) -> dict[str, Any]:
    return loads(path.read_text(encoding="utf-8"))
