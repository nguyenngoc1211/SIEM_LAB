"""Baseline B2: let Gemini choose the ATT&CK technique on its own."""

from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Any

from .base import StrategyResult, clamp_confidence, load_catalog


ALLOWED_STATUS = {"mapped", "uncertain", "insufficient_evidence"}
CODE_FENCE_RE = re.compile(r"^```(?:json)?\s*|\s*```$", re.IGNORECASE)
DAILY_QUOTA_RETRY_THRESHOLD_SECONDS = 600.0


class QuotaExhausted(RuntimeError):
    """Raised when the daily request quota is gone and waiting will not help."""

RESPONSE_SCHEMA: dict[str, Any] = {
    "type": "OBJECT",
    "properties": {
        "mapping_status": {
            "type": "STRING",
            "enum": ["mapped", "uncertain", "insufficient_evidence"],
            "description": "Decision made from the alert behavior only.",
        },
        "primary_technique_id": {
            "type": "STRING",
            "description": "Selected ATT&CK id, or an empty string when abstaining.",
        },
        "primary_technique_name": {"type": "STRING"},
        "confidence": {"type": "NUMBER"},
        "ranked_candidates": {
            "type": "ARRAY",
            "maxItems": 3,
            "items": {
                "type": "OBJECT",
                "properties": {
                    "technique_id": {"type": "STRING"},
                    "confidence": {"type": "NUMBER"},
                    "reason": {"type": "STRING"},
                },
                "required": ["technique_id", "confidence", "reason"],
            },
        },
        "evidence": {
            "type": "ARRAY",
            "maxItems": 8,
            "items": {"type": "STRING"},
        },
        "rationale": {"type": "STRING"},
        "uncertainty": {"type": "STRING"},
    },
    "required": [
        "mapping_status",
        "primary_technique_id",
        "primary_technique_name",
        "confidence",
        "ranked_candidates",
        "evidence",
        "rationale",
        "uncertainty",
    ],
}


class GeminiOnlyStrategy:
    """Prompt-based LLM baseline with pinned prompt, schema, and model."""

    name = "gemini_only"
    version = "1.0.0"

    def __init__(
        self,
        project_root: Path,
        *,
        model: str = "gemini-2.5-flash",
        mode: str = "closed_set",
        temperature: float = 0.0,
        repeats: int = 1,
        max_output_tokens: int = 2048,
        thinking_budget: int | None = None,
        request_timeout: float = 120.0,
        max_retries: int = 3,
        delay_seconds: float = 0.0,
        backoff_cap_seconds: float = 90.0,
        api_base: str = "https://generativelanguage.googleapis.com",
        prompt_path: Path | None = None,
        api_key: str | None = None,
        api_key_env: str = "GEMINI_API_KEY",
        dry_run: bool = False,
    ) -> None:
        if mode not in {"closed_set", "open_set"}:
            raise ValueError("mode must be 'closed_set' or 'open_set'")
        self.project_root = Path(project_root)
        self.model = os.getenv("GEMINI_MODEL", model).strip() or model
        self.mode = mode
        self.temperature = float(temperature)
        self.repeats = max(1, int(repeats))
        self.max_output_tokens = int(max_output_tokens)
        self.thinking_budget = None if thinking_budget is None else int(thinking_budget)
        self.request_timeout = float(request_timeout)
        self.max_retries = max(0, int(max_retries))
        env_interval = os.getenv("GEMINI_MIN_INTERVAL_SECONDS")
        self.delay_seconds = max(
            0.0,
            float(env_interval) if env_interval else float(delay_seconds),
        )
        self.backoff_cap_seconds = max(1.0, float(backoff_cap_seconds))
        self._last_call_started = 0.0
        self.api_base = api_base.rstrip("/")
        self.api_key_env = api_key_env
        self.api_key = (
            api_key if api_key is not None else os.getenv(api_key_env, "")
        ).strip()
        self.prompt_template_path = prompt_path or (self.project_root / "prompts" / "gemini_only_v1.md")
        self.prompt_template = self.prompt_template_path.read_text(encoding="utf-8")
        self.prompt_version = "gemini-only-1.0.0"
        self.catalog = load_catalog(
            self.project_root / "artifacts" / "attack" / "attack_final.mapping.json"
        )
        self.ids = {item["technique_id"] for item in self.catalog}
        self.name_by_id = {item["technique_id"]: item["name"] for item in self.catalog}
        self.dry_run = bool(dry_run) or not self.api_key
        self.skip_reason = (
            "dry_run requested" if dry_run else
            f"{self.api_key_env} is not configured" if not self.api_key else None
        )

    def build_prompt(self, alert: dict[str, Any]) -> str:
        catalog = self.catalog if self.mode == "closed_set" else []
        return (
            self.prompt_template
            .replace("{{MODE}}", self.mode)
            .replace("{{OUTPUT_LANGUAGE}}", "Vietnamese")
            .replace(
                "{{ALERT_JSON}}",
                json.dumps(alert, ensure_ascii=False, indent=2),
            )
            .replace(
                "{{CATALOG_JSON}}",
                json.dumps(catalog, ensure_ascii=False, indent=2),
            )
        )

    def map_alert(
        self, alert: dict[str, Any], scenario_id: str | None = None,
    ) -> StrategyResult:
        runs: list[StrategyResult] = []
        for index in range(self.repeats):
            if index and self.delay_seconds:
                time.sleep(self.delay_seconds)
            runs.append(self._single_run(alert, scenario_id, index))
        primary = runs[0]
        if len(runs) > 1:
            primary.details["runs"] = [
                {
                    "run_index": index,
                    "mapping_status": run.mapping_status,
                    "primary_technique_id": (run.primary_mapping or {}).get("technique_id"),
                    "latency_ms": run.latency_ms,
                    "errors": run.details.get("errors", []),
                    "invalid_ids": run.details.get("invalid_ids", []),
                }
                for index, run in enumerate(runs)
            ]
            primary.details["consensus"] = self._consensus(runs)
        return primary

    def _single_run(
        self, alert: dict[str, Any], scenario_id: str | None, run_index: int,
    ) -> StrategyResult:
        started = time.perf_counter()
        prompt = self.build_prompt(alert)
        base_details: dict[str, Any] = {
            "strategy_version": self.version,
            "model": self.model,
            "prompt_version": self.prompt_version,
            "mode": self.mode,
            "temperature": self.temperature,
            "repeats": self.repeats,
            "run_index": run_index,
            "prompt_chars": len(prompt),
            "errors": [],
            "invalid_ids": [],
        }
        if self.dry_run:
            elapsed_ms = round((time.perf_counter() - started) * 1000, 3)
            base_details["errors"].append(f"skipped: {self.skip_reason}")
            return StrategyResult(
                strategy=self.name,
                scenario_id=scenario_id,
                mapping_status="skipped",
                primary_mapping=None,
                latency_ms=elapsed_ms,
                details=base_details,
            )

        response, error, latency_ms = self._call_gemini(prompt)
        base_details["api_latency_ms"] = latency_ms
        if error:
            base_details["errors"].append(error)
            elapsed_ms = round((time.perf_counter() - started) * 1000, 3)
            return StrategyResult(
                strategy=self.name,
                scenario_id=scenario_id,
                mapping_status="error",
                primary_mapping=None,
                latency_ms=elapsed_ms,
                details=base_details,
            )

        base_details["model_version"] = response.get("modelVersion")
        base_details["usage"] = response.get("usageMetadata")
        candidate = (response.get("candidates") or [{}])[0]
        base_details["finish_reason"] = candidate.get("finishReason")
        if response.get("promptFeedback", {}).get("blockReason"):
            base_details["errors"].append(
                f"prompt blocked: {response['promptFeedback']['blockReason']}"
            )
        raw_text = self._extract_text(candidate)
        base_details["raw_text"] = raw_text[:4000]
        base_details["raw_response"] = json.dumps(response, ensure_ascii=False)[:4000]

        try:
            parsed = json.loads(CODE_FENCE_RE.sub("", raw_text).strip())
        except (json.JSONDecodeError, AttributeError) as exc:
            base_details["errors"].append(f"json_parse_error: {exc}")
            elapsed_ms = round((time.perf_counter() - started) * 1000, 3)
            return StrategyResult(
                strategy=self.name,
                scenario_id=scenario_id,
                mapping_status="invalid_output",
                primary_mapping=None,
                latency_ms=elapsed_ms,
                details=base_details,
            )

        result = self._validate(parsed, base_details)
        result.scenario_id = scenario_id
        result.latency_ms = round((time.perf_counter() - started) * 1000, 3)
        return result

    @staticmethod
    def _extract_text(candidate: dict[str, Any]) -> str:
        content = candidate.get("content") if isinstance(candidate, dict) else None
        parts = content.get("parts") if isinstance(content, dict) else None
        if not isinstance(parts, list):
            return ""
        return "\n".join(
            part.get("text", "")
            for part in parts
            if isinstance(part, dict) and isinstance(part.get("text"), str)
        ).strip()

    def _call_gemini(self, prompt: str) -> tuple[dict[str, Any], str | None, float]:
        url = f"{self.api_base}/v1beta/models/{self.model}:generateContent"
        payload = {
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": self.temperature,
                "maxOutputTokens": self.max_output_tokens,
                "responseMimeType": "application/json",
                "responseSchema": RESPONSE_SCHEMA,
            },
        }
        if self.thinking_budget is not None:
            payload["generationConfig"]["thinkingConfig"] = {
                "thinkingBudget": self.thinking_budget
            }
        last_error = "unknown Gemini error"
        for attempt in range(self.max_retries + 1):
            self._pace()
            started = time.perf_counter()
            request = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                method="POST",
            )
            request.add_header("Content-Type", "application/json")
            request.add_header("x-goog-api-key", self.api_key)
            try:
                with urllib.request.urlopen(request, timeout=self.request_timeout) as response:
                    body = response.read()
                latency_ms = round((time.perf_counter() - started) * 1000, 3)
                return json.loads(body), None, latency_ms
            except urllib.error.HTTPError as exc:
                detail = ""
                try:
                    detail = exc.read().decode("utf-8", errors="replace")[:600]
                except Exception:
                    pass
                last_error = (
                    f"HTTP {exc.code} (attempt {attempt + 1}/{self.max_retries + 1}): "
                    f"{detail or exc.reason}"
                )
                if exc.code not in {429, 500, 502, 503, 504}:
                    break
                hinted = self._retry_delay_seconds(detail)
                if exc.code == 429 and hinted >= DAILY_QUOTA_RETRY_THRESHOLD_SECONDS:
                    raise QuotaExhausted(
                        f"daily quota exhausted, retry after ~{hinted:.0f}s: {detail[:300]}"
                    ) from exc
                if attempt < self.max_retries:
                    backoff = min(self.backoff_cap_seconds, 2.0 ** attempt)
                    time.sleep(max(hinted, backoff))
                continue
            except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
                last_error = (
                    f"{type(exc).__name__} (attempt {attempt + 1}/"
                    f"{self.max_retries + 1}): {exc}"
                )
            if attempt < self.max_retries:
                time.sleep(min(self.backoff_cap_seconds, 2.0 ** attempt))
        return {}, last_error, 0.0

    def _pace(self) -> None:
        """Respect the configured minimum interval between API requests."""

        if self.delay_seconds <= 0:
            return
        now = time.monotonic()
        wait = self.delay_seconds - (now - self._last_call_started)
        if wait > 0:
            time.sleep(wait)
        self._last_call_started = time.monotonic()

    @staticmethod
    def _retry_delay_seconds(detail: str) -> float:
        """Read the retryDelay hint from a Gemini error payload."""

        match = re.search(r'"retryDelay"\s*:\s*"(\d+(?:\.\d+)?)s"', detail or "")
        if not match:
            return 0.0
        return min(120.0, float(match.group(1)))

    def _validate(
        self, parsed: dict[str, Any], details: dict[str, Any],
    ) -> StrategyResult:
        status = str(parsed.get("mapping_status") or "").strip().lower()
        if status not in ALLOWED_STATUS:
            details["errors"].append(f"invalid mapping_status: {status!r}")
            status = "invalid_output"

        ranked: list[dict[str, Any]] = []
        for item in parsed.get("ranked_candidates") or []:
            if not isinstance(item, dict):
                continue
            technique_id = str(item.get("technique_id") or "").strip().upper()
            if not technique_id:
                continue
            if technique_id not in self.ids:
                details["invalid_ids"].append(technique_id)
                continue
            ranked.append({
                "technique_id": technique_id,
                "name": self.name_by_id.get(technique_id, technique_id),
                "confidence": clamp_confidence(item.get("confidence")),
                "reason": str(item.get("reason") or "").strip(),
            })

        primary_id = str(parsed.get("primary_technique_id") or "").strip().upper()
        primary: dict[str, Any] | None = None
        if primary_id and primary_id not in self.ids:
            details["invalid_ids"].append(primary_id)
            details["errors"].append(f"primary technique outside supported subset: {primary_id}")
            status = "invalid_output"
            primary_id = ""

        if status == "insufficient_evidence":
            primary_id = ""
        elif not primary_id:
            details["errors"].append("mapped decision without a valid primary technique id")
            status = "invalid_output"

        if primary_id:
            primary = {
                "technique_id": primary_id,
                "name": self.name_by_id.get(primary_id, primary_id),
                "confidence": clamp_confidence(parsed.get("confidence")),
            }
            if not any(item["technique_id"] == primary_id for item in ranked):
                ranked.insert(0, {**primary, "reason": "Primary selection returned by Gemini."})

        alternatives = [
            {
                "technique_id": item["technique_id"],
                "name": item["name"],
                "confidence": item["confidence"],
                "rejection_reason": item["reason"] or "Ranked below the primary technique.",
            }
            for item in ranked
            if item["technique_id"] != primary_id
        ][:3]
        trace = [
            {
                "technique_id": item["technique_id"],
                "name": item["name"],
                "rank": rank,
                "confidence": item["confidence"],
                "reason": item["reason"],
            }
            for rank, item in enumerate(ranked, 1)
        ]
        details["evidence"] = [
            str(value) for value in (parsed.get("evidence") or []) if str(value).strip()
        ][:8]
        details["rationale"] = str(parsed.get("rationale") or "").strip()
        details["uncertainty"] = str(parsed.get("uncertainty") or "").strip()
        details["ranked_candidate_count"] = len(ranked)
        return StrategyResult(
            strategy=self.name,
            scenario_id=None,
            mapping_status=status,
            primary_mapping=primary,
            alternative_candidates=alternatives,
            candidate_trace=trace,
            details=details,
        )

    @staticmethod
    def _consensus(runs: list[StrategyResult]) -> dict[str, Any]:
        votes: Counter[str] = Counter()
        order: list[str] = []
        for run in runs:
            technique_id = (run.primary_mapping or {}).get("technique_id")
            if not technique_id:
                continue
            if technique_id not in votes:
                order.append(technique_id)
            votes[technique_id] += 1
        if not votes:
            return {
                "mapping_status": "insufficient_evidence",
                "primary_technique_id": None,
                "votes": {},
                "agreement": 0.0,
            }
        winner = max(order, key=lambda technique_id: (votes[technique_id], -order.index(technique_id)))
        return {
            "mapping_status": "mapped",
            "primary_technique_id": winner,
            "votes": dict(votes),
            "agreement": round(votes[winner] / len(runs), 6),
        }
