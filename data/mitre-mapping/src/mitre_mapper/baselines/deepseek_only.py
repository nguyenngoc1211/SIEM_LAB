"""Baseline B2: let DeepSeek choose the ATT&CK technique on its own.

DeepSeek exposes an OpenAI-compatible ``/chat/completions`` endpoint, so this
strategy keeps the B2 contract of the previous Gemini baseline (pinned prompt,
closed-set catalog, fixed output fields, abstention) while driving it through
DeepSeek's JSON output mode.

Two behaviours matter for a long evaluation run:

* ``response_format = {"type": "json_object"}`` replaces Gemini's
  ``responseSchema``, so the required JSON shape is documented inside the
  prompt instead of being enforced by the provider.
* the request interval adapts to the provider status. It only widens when the
  API answers 429/5xx and relaxes back toward the configured base pace after a
  streak of successful calls, which keeps the run inside the rate limit
  without slowing down a healthy provider.
"""

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
RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}


class QuotaExhausted(RuntimeError):
    """Raised when the provider quota is gone and waiting will not help."""


class DeepSeekOnlyStrategy:
    """Prompt-based LLM baseline with pinned prompt, schema, and model."""

    name = "deepseek_only"
    version = "1.0.0"

    def __init__(
        self,
        project_root: Path,
        *,
        model: str = "deepseek-flash",
        mode: str = "closed_set",
        temperature: float = 0.0,
        repeats: int = 1,
        max_output_tokens: int = 8192,
        request_timeout: float = 180.0,
        max_retries: int = 2,
        delay_seconds: float = 1.5,
        backoff_cap_seconds: float = 60.0,
        api_base: str = "https://api.deepseek.com",
        prompt_path: Path | None = None,
        api_key: str | None = None,
        api_key_env: str = "DEEPSEEK_API_KEY_NCKH",
        dry_run: bool = False,
    ) -> None:
        if mode not in {"closed_set", "open_set"}:
            raise ValueError("mode must be 'closed_set' or 'open_set'")
        self.project_root = Path(project_root)
        self.model = os.getenv("DEEPSEEK_MODEL", model).strip() or model
        self.mode = mode
        self.temperature = float(temperature)
        self.repeats = max(1, int(repeats))
        self.max_output_tokens = int(max_output_tokens)
        self.request_timeout = float(request_timeout)
        self.max_retries = max(0, int(max_retries))
        self.backoff_cap_seconds = max(1.0, float(backoff_cap_seconds))
        base_interval = max(0.0, float(delay_seconds))
        env_interval = os.getenv("DEEPSEEK_MIN_INTERVAL_SECONDS")
        self.base_interval = max(
            0.0, float(env_interval) if env_interval else base_interval
        )
        # ``delay_seconds`` stays the live interval so runner signatures and
        # older tooling keep working, but it is re-derived from the base pace
        # after successful calls.
        self.delay_seconds = self.base_interval
        self.max_interval_seconds = max(self.base_interval * 8.0, 20.0)
        self._last_call_started = 0.0
        self._success_streak = 0
        self.api_base = api_base.rstrip("/")
        self.api_key_env = api_key_env
        self.api_key = (
            api_key if api_key is not None else os.getenv(api_key_env, "")
        ).strip()
        self.prompt_template_path = prompt_path or (
            self.project_root / "prompts" / "deepseek_only_v1.md"
        )
        self.prompt_template = self.prompt_template_path.read_text(encoding="utf-8")
        self.prompt_version = "deepseek-only-1.0.0"
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
            "provider": "deepseek",
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

        response, error, latency_ms = self._call_deepseek(prompt)
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

        base_details["model_version"] = response.get("model")
        base_details["usage"] = response.get("usage")
        choices = response.get("choices") or []
        candidate = choices[0] if choices and isinstance(choices[0], dict) else {}
        base_details["finish_reason"] = candidate.get("finish_reason")
        if candidate.get("finish_reason") == "length":
            base_details["errors"].append("output truncated: finish_reason=length")
        message = candidate.get("message") if isinstance(candidate.get("message"), dict) else {}
        if message.get("reasoning_content"):
            base_details["reasoning_chars"] = len(str(message["reasoning_content"]))
        raw_text = str(message.get("content") or "").strip()
        base_details["raw_text"] = raw_text[:4000]
        base_details["raw_response"] = json.dumps(response, ensure_ascii=False)[:4000]

        parsed = self._parse_json(raw_text)
        if parsed is None:
            base_details["errors"].append("json_parse_error: model did not return a JSON object")
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
    def _parse_json(raw_text: str) -> dict[str, Any] | None:
        if not raw_text:
            return None
        stripped = CODE_FENCE_RE.sub("", raw_text).strip()
        try:
            parsed = json.loads(stripped)
        except (json.JSONDecodeError, AttributeError, TypeError):
            # Reasoning models occasionally wrap the object in prose; recover
            # the outer-most JSON object before giving up.
            start = stripped.find("{")
            end = stripped.rfind("}")
            if start == -1 or end <= start:
                return None
            try:
                parsed = json.loads(stripped[start:end + 1])
            except json.JSONDecodeError:
                return None
        return parsed if isinstance(parsed, dict) else None

    def _call_deepseek(self, prompt: str) -> tuple[dict[str, Any], str | None, float]:
        url = f"{self.api_base}/chat/completions"
        payload = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are a SOC analyst that returns a single strict JSON object. "
                        "Never wrap the JSON in markdown fences."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            "temperature": self.temperature,
            "max_tokens": self.max_output_tokens,
            "response_format": {"type": "json_object"},
            "stream": False,
        }
        last_error = "unknown DeepSeek error"
        attempt = 0
        while attempt <= self.max_retries:
            self._pace()
            started = time.perf_counter()
            request = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                method="POST",
            )
            request.add_header("Content-Type", "application/json")
            request.add_header("Authorization", f"Bearer {self.api_key}")
            try:
                with urllib.request.urlopen(request, timeout=self.request_timeout) as response:
                    body = response.read()
                latency_ms = round((time.perf_counter() - started) * 1000, 3)
                self._note_success()
                return json.loads(body), None, latency_ms
            except urllib.error.HTTPError as exc:
                detail = ""
                try:
                    detail = exc.read().decode("utf-8", errors="replace")[:600]
                except Exception:  # noqa: BLE001 - best-effort error body
                    pass
                last_error = (
                    f"HTTP {exc.code} (attempt {attempt + 1}/{self.max_retries + 1}): "
                    f"{detail or exc.reason}"
                )
                if self._is_fatal(exc.code, detail):
                    raise QuotaExhausted(
                        f"provider quota/balance problem (HTTP {exc.code}): {detail[:300]}"
                    ) from exc
                if exc.code not in RETRYABLE_STATUS_CODES:
                    break
                hinted = self._retry_delay_seconds(detail)
                if exc.code == 429 and hinted >= DAILY_QUOTA_RETRY_THRESHOLD_SECONDS:
                    raise QuotaExhausted(
                        f"daily quota exhausted, retry after ~{hinted:.0f}s: {detail[:300]}"
                    ) from exc
                self._note_throttle(exc.code)
                if attempt < self.max_retries:
                    backoff = min(self.backoff_cap_seconds, 2.0 ** attempt)
                    time.sleep(max(hinted, backoff))
            except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
                last_error = (
                    f"{type(exc).__name__} (attempt {attempt + 1}/"
                    f"{self.max_retries + 1}): {exc}"
                )
                self._note_throttle(None)
                if attempt < self.max_retries:
                    time.sleep(min(self.backoff_cap_seconds, 2.0 ** attempt))
            attempt += 1
        return {}, last_error, 0.0

    @staticmethod
    def _is_fatal(status_code: int, detail: str) -> bool:
        """Detect non-retryable provider states such as empty balance."""

        if status_code in {401, 402, 403}:
            return True
        lowered = (detail or "").lower()
        return "insufficient balance" in lowered or "insufficient_quota" in lowered

    def _pace(self) -> None:
        """Respect the current minimum interval between API requests."""

        if self.delay_seconds <= 0:
            self._last_call_started = time.monotonic()
            return
        now = time.monotonic()
        wait = self.delay_seconds - (now - self._last_call_started)
        if wait > 0:
            time.sleep(wait)
        self._last_call_started = time.monotonic()

    def _note_success(self) -> None:
        """Relax the pacing gradually after a healthy call."""

        self._success_streak += 1
        if self.delay_seconds > self.base_interval and self._success_streak >= 3:
            self.delay_seconds = max(
                self.base_interval, round(self.delay_seconds * 0.7, 3)
            )
            self._success_streak = 0

    def _note_throttle(self, status_code: int | None) -> None:
        """Widen the pacing gently when the provider pushes back."""

        self._success_streak = 0
        widened = max(self.delay_seconds * 2.0, self.base_interval + 1.0)
        self.delay_seconds = round(min(self.max_interval_seconds, widened), 3)
        self.last_throttle_status = status_code

    @staticmethod
    def _retry_delay_seconds(detail: str) -> float:
        """Read a retry hint from the DeepSeek error payload."""

        text = detail or ""
        match = re.search(r'"retry_after"\s*:\s*(\d+(?:\.\d+)?)', text)
        if not match:
            match = re.search(r'"retryDelay"\s*:\s*"(\d+(?:\.\d+)?)s"', text)
        if not match:
            match = re.search(r"retry after\s*(\d+(?:\.\d+)?)\s*s", text, re.IGNORECASE)
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
            details["errors"].append(
                f"primary technique outside supported subset: {primary_id}"
            )
            status = "invalid_output"
            primary_id = ""

        if status == "insufficient_evidence":
            primary_id = ""
        elif not primary_id:
            details["errors"].append(
                "mapped decision without a valid primary technique id"
            )
            status = "invalid_output"

        if primary_id:
            primary = {
                "technique_id": primary_id,
                "name": self.name_by_id.get(primary_id, primary_id),
                "confidence": clamp_confidence(parsed.get("confidence")),
            }
            if not any(item["technique_id"] == primary_id for item in ranked):
                ranked.insert(
                    0, {**primary, "reason": "Primary selection returned by DeepSeek."}
                )

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
        winner = max(
            order, key=lambda technique_id: (votes[technique_id], -order.index(technique_id))
        )
        return {
            "mapping_status": "mapped",
            "primary_technique_id": winner,
            "votes": dict(votes),
            "agreement": round(votes[winner] / len(runs), 6),
        }
