from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    project_root: Path
    database_path: Path
    documents_path: Path
    bm25_path: Path
    manifest_path: Path
    qdrant_url: str
    embedding_url: str
    reranker_url: str
    collection_name: str
    request_timeout: float
    dense_weight: float
    sparse_weight: float
    retrieval_weight: float
    reranker_weight: float
    evidence_weight: float
    decision_threshold: float
    uncertainty_margin: float
    local_fallback: bool
    api_key: str

    @classmethod
    def load(cls, project_root: Path | None = None) -> "Settings":
        root = (project_root or PROJECT_ROOT).resolve()
        config_path = root / "configs" / "settings.json"
        raw: dict[str, Any] = {}
        if config_path.exists():
            raw = json.loads(config_path.read_text(encoding="utf-8"))

        def path_env(name: str, default: str) -> Path:
            value = Path(os.getenv(name, default))
            return value if value.is_absolute() else root / value

        return cls(
            project_root=root,
            database_path=path_env("ATTACK_DB_PATH", raw.get("database_path", "artifacts/attack/attack_final.mapping.json")),
            documents_path=path_env("DOCUMENTS_PATH", raw.get("documents_path", "artifacts/retrieval/technique_documents.jsonl")),
            bm25_path=path_env("BM25_PATH", raw.get("bm25_path", "artifacts/retrieval/bm25_index.json")),
            manifest_path=path_env("MANIFEST_PATH", raw.get("manifest_path", "artifacts/attack/index_manifest.json")),
            qdrant_url=os.getenv("QDRANT_URL", raw.get("qdrant_url", "http://localhost:6333")).rstrip("/"),
            embedding_url=os.getenv("EMBEDDING_URL", raw.get("embedding_url", "http://localhost:8080")).rstrip("/"),
            reranker_url=os.getenv("RERANKER_URL", raw.get("reranker_url", "http://localhost:8082")).rstrip("/"),
            collection_name=os.getenv("QDRANT_COLLECTION", raw.get("collection_name", "attack_techniques_v1")),
            request_timeout=float(os.getenv("REQUEST_TIMEOUT", raw.get("request_timeout", 60))),
            dense_weight=float(raw.get("dense_weight", 0.6)),
            sparse_weight=float(raw.get("sparse_weight", 0.4)),
            retrieval_weight=float(raw.get("retrieval_weight", 0.3)),
            reranker_weight=float(raw.get("reranker_weight", 0.5)),
            evidence_weight=float(raw.get("evidence_weight", 0.2)),
            decision_threshold=float(raw.get("decision_threshold", 0.55)),
            uncertainty_margin=float(raw.get("uncertainty_margin", 0.07)),
            local_fallback=_env_bool("LOCAL_FALLBACK", bool(raw.get("local_fallback", True))),
            api_key=os.getenv("MAPPER_API_KEY", ""),
        )
