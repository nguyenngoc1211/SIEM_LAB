from __future__ import annotations

import json
import math
import urllib.error
import urllib.request
import uuid
from collections import Counter
from pathlib import Path
from typing import Any

from .database import build_query_vector, read_json, read_jsonl, tokenize
from .settings import Settings


class ServiceError(RuntimeError):
    pass


def request_json(method: str, url: str, payload: Any = None, timeout: float = 60) -> Any:
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(url, data=data, method=method)
    request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read()
            return json.loads(body) if body else None
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as exc:
        detail = ""
        if isinstance(exc, urllib.error.HTTPError):
            try:
                detail = exc.read().decode("utf-8", errors="replace")[:1000]
            except Exception:
                pass
        raise ServiceError(f"{method} {url} failed: {exc}. {detail}".strip()) from exc


def probe_http(url: str, timeout: float = 5) -> Any:
    """Require a successful HTTP response without assuming a JSON body."""
    request = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read()
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as exc:
        raise ServiceError(f"GET {url} failed: {exc}") from exc

    if not body:
        return None
    try:
        return json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return body.decode("utf-8", errors="replace")[:300]


class EmbeddingClient:
    def __init__(self, url: str, timeout: float = 60):
        self.url = url.rstrip("/")
        self.timeout = timeout

    def embed(self, texts: list[str]) -> list[list[float]]:
        response = request_json(
            "POST",
            f"{self.url}/embed",
            {"inputs": texts, "normalize": True, "truncate": True},
            self.timeout,
        )
        if not isinstance(response, list) or not response or not isinstance(response[0], list):
            raise ServiceError(f"Unexpected TEI response: {str(response)[:300]}")
        return response


class QdrantClient:
    def __init__(self, url: str, collection: str, timeout: float = 60):
        self.url = url.rstrip("/")
        self.collection = collection
        self.timeout = timeout

    def collection_info(self) -> dict[str, Any] | None:
        try:
            return request_json("GET", f"{self.url}/collections/{self.collection}", timeout=self.timeout)
        except ServiceError as exc:
            if "404" in str(exc):
                return None
            raise

    def create_collection(self, dense_size: int, recreate: bool = False) -> None:
        existing = self.collection_info()
        if existing and recreate:
            request_json("DELETE", f"{self.url}/collections/{self.collection}", timeout=self.timeout)
            existing = None
        if existing:
            config = (((existing.get("result") or {}).get("config") or {}).get("params") or {})
            dense = (config.get("vectors") or {}).get("dense") or {}
            if dense.get("size") not in (None, dense_size):
                raise ServiceError(
                    f"Collection {self.collection} uses dense size {dense.get('size')}, expected {dense_size}. "
                    "Run the build script with --recreate."
                )
            return
        request_json(
            "PUT",
            f"{self.url}/collections/{self.collection}",
            {
                "vectors": {"dense": {"size": dense_size, "distance": "Cosine"}},
                "sparse_vectors": {"sparse": {"index": {"on_disk": False}}},
                "on_disk_payload": True,
            },
            self.timeout,
        )

    def upsert(self, points: list[dict[str, Any]]) -> None:
        request_json(
            "PUT",
            f"{self.url}/collections/{self.collection}/points?wait=true",
            {"points": points},
            self.timeout,
        )

    def query(self, vector: Any, using: str, limit: int) -> list[dict[str, Any]]:
        response = request_json(
            "POST",
            f"{self.url}/collections/{self.collection}/points/query",
            {"query": vector, "using": using, "limit": limit, "with_payload": True},
            self.timeout,
        )
        result = response.get("result", {}) if isinstance(response, dict) else {}
        if isinstance(result, list):
            return result
        return result.get("points", [])


def point_id(technique_id: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"https://attack.mitre.org/techniques/{technique_id}"))


def build_qdrant_index(settings: Settings, recreate: bool = False) -> dict[str, Any]:
    documents = read_jsonl(settings.documents_path)
    bm25 = read_json(settings.bm25_path)
    manifest = read_json(settings.manifest_path)
    embeddings = EmbeddingClient(settings.embedding_url, settings.request_timeout).embed(
        [document["dense_text"] for document in documents]
    )
    if len(embeddings) != len(documents):
        raise ServiceError("Embedding count differs from document count")
    dense_size = len(embeddings[0])
    qdrant = QdrantClient(settings.qdrant_url, settings.collection_name, settings.request_timeout)
    qdrant.create_collection(dense_size, recreate=recreate)
    points = []
    for document, dense in zip(documents, embeddings):
        technique_id = document["technique_id"]
        payload = dict(document["payload"])
        payload.update({
            "sparse_text": document["sparse_text"],
            "index_version": manifest["index_version"],
            "attack_final_sha256": manifest["attack_final_sha256"],
        })
        points.append({
            "id": point_id(technique_id),
            "vector": {"dense": dense, "sparse": bm25["document_vectors"][technique_id]},
            "payload": payload,
        })
    for start in range(0, len(points), 32):
        qdrant.upsert(points[start : start + 32])
    return {
        "collection": settings.collection_name,
        "points": len(points),
        "dense_size": dense_size,
        "index_version": manifest["index_version"],
    }


def _normalize(scores: dict[str, float]) -> dict[str, float]:
    if not scores:
        return {}
    low, high = min(scores.values()), max(scores.values())
    if math.isclose(low, high):
        return {key: 1.0 for key in scores}
    return {key: (value - low) / (high - low) for key, value in scores.items()}


def _matched_terms(query: str, sparse_text: str, limit: int = 12) -> list[str]:
    query_terms = set(tokenize(query))
    document_terms = set(tokenize(sparse_text))
    return sorted(query_terms & document_terms)[:limit]


class HybridRetriever:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.documents = read_jsonl(settings.documents_path)
        self.by_id = {document["technique_id"]: document for document in self.documents}
        self.bm25 = read_json(settings.bm25_path)
        self.embedding = EmbeddingClient(settings.embedding_url, settings.request_timeout)
        self.qdrant = QdrantClient(settings.qdrant_url, settings.collection_name, settings.request_timeout)

    def retrieve(self, text: str, dense_limit: int = 30, sparse_limit: int = 30, fusion_limit: int = 20) -> tuple[list[dict[str, Any]], list[str]]:
        degraded: list[str] = []
        try:
            dense_vector = self.embedding.embed([text])[0]
            sparse_vector = build_query_vector(text, self.bm25)
            dense_points = self.qdrant.query(dense_vector, "dense", dense_limit)
            sparse_points = self.qdrant.query(sparse_vector, "sparse", sparse_limit) if sparse_vector["indices"] else []
            dense_raw = {point["payload"]["technique_id"]: float(point["score"]) for point in dense_points}
            sparse_raw = {point["payload"]["technique_id"]: float(point["score"]) for point in sparse_points}
        except ServiceError as exc:
            if not self.settings.local_fallback:
                raise
            degraded.append(f"local_retrieval_fallback: {exc}")
            sparse_raw, dense_raw = self._local_scores(text)

        dense_scores = _normalize(dense_raw)
        sparse_scores = _normalize(sparse_raw)
        candidates = []
        for technique_id in set(dense_scores) | set(sparse_scores):
            document = self.by_id.get(technique_id)
            if not document:
                continue
            fusion = (
                self.settings.dense_weight * dense_scores.get(technique_id, 0.0)
                + self.settings.sparse_weight * sparse_scores.get(technique_id, 0.0)
            )
            candidates.append({
                "technique_id": technique_id,
                "name": document["name"],
                "dense_score": round(dense_scores.get(technique_id, 0.0), 6),
                "bm25_score": round(sparse_scores.get(technique_id, 0.0), 6),
                "fusion_score": round(fusion, 6),
                "matched_terms": _matched_terms(text, document["sparse_text"]),
                "document": document,
            })
        candidates.sort(key=lambda value: (-value["fusion_score"], value["technique_id"]))
        for rank, candidate in enumerate(candidates, 1):
            candidate["rank_before_rerank"] = rank
        return candidates[:fusion_limit], degraded

    def _local_scores(self, text: str) -> tuple[dict[str, float], dict[str, float]]:
        query_vector = build_query_vector(text, self.bm25)
        query_weights = dict(zip(query_vector["indices"], query_vector["values"]))
        query_terms = Counter(tokenize(text))
        sparse_scores: dict[str, float] = {}
        dense_scores: dict[str, float] = {}
        for document in self.documents:
            technique_id = document["technique_id"]
            vector = self.bm25["document_vectors"][technique_id]
            sparse_scores[technique_id] = sum(
                value * query_weights.get(index, 0.0)
                for index, value in zip(vector["indices"], vector["values"])
            )
            document_terms = Counter(tokenize(document["dense_text"]))
            numerator = sum(query_terms[term] * document_terms[term] for term in query_terms)
            qnorm = math.sqrt(sum(value * value for value in query_terms.values()))
            dnorm = math.sqrt(sum(value * value for value in document_terms.values()))
            dense_scores[technique_id] = numerator / (qnorm * dnorm) if qnorm and dnorm else 0.0
        return sparse_scores, dense_scores


class CrossEncoderReranker:
    def __init__(self, settings: Settings):
        self.settings = settings

    def rerank(self, alert_text: str, candidates: list[dict[str, Any]], limit: int = 5) -> tuple[list[dict[str, Any]], list[str], str]:
        if not candidates:
            return [], [], "cross-encoder/ms-marco-MiniLM-L-6-v2"
        texts = [candidate["document"]["dense_text"] for candidate in candidates]
        degraded: list[str] = []
        try:
            response = request_json(
                "POST",
                f"{self.settings.reranker_url}/rerank",
                {"query": alert_text, "texts": texts, "raw_scores": False},
                self.settings.request_timeout,
            )
            rows = response.get("results", response) if isinstance(response, dict) else response
            if not isinstance(rows, list):
                raise ServiceError(f"Unexpected reranker response: {str(response)[:300]}")
            raw_by_index = {int(row["index"]): float(row.get("score", row.get("raw_score"))) for row in rows}
            normalized = _normalize({str(index): score for index, score in raw_by_index.items()})
            for index, candidate in enumerate(candidates):
                candidate["reranker_raw_score"] = raw_by_index.get(index, 0.0)
                candidate["reranker_score"] = normalized.get(str(index), 0.0)
            if isinstance(response, dict):
                model_version = f"{response.get('model', 'cross-encoder/ms-marco-MiniLM-L-6-v2')}@{response.get('revision', 'unknown')}"
            else:
                model_version = "cross-encoder/ms-marco-MiniLM-L-6-v2@unknown"
        except (ServiceError, KeyError, TypeError, ValueError) as exc:
            if not self.settings.local_fallback:
                raise ServiceError(str(exc)) from exc
            degraded.append(f"lexical_reranker_fallback: {exc}")
            query_terms = set(tokenize(alert_text))
            for candidate in candidates:
                document_terms = set(tokenize(candidate["document"]["dense_text"]))
                overlap = len(query_terms & document_terms) / max(len(query_terms), 1)
                candidate["reranker_raw_score"] = overlap
                candidate["reranker_score"] = min(
                    1.0, 0.55 * candidate["fusion_score"] + 0.45 * overlap,
                )
            model_version = "lexical-fallback-1.0.0"
        candidates.sort(key=lambda value: (-value["reranker_score"], value["rank_before_rerank"]))
        for rank, candidate in enumerate(candidates, 1):
            candidate["rank_after_rerank"] = rank
            candidate["reranker_score"] = round(candidate["reranker_score"], 6)
        return candidates[:limit], degraded, model_version
