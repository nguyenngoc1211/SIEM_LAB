from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse

from .clients import QdrantClient, ServiceError, probe_http
from .pipeline import MappingPipeline
from .settings import Settings


settings = Settings.load()
pipeline: MappingPipeline | None = None


@asynccontextmanager
async def lifespan(_: FastAPI):
    global pipeline
    pipeline = MappingPipeline(settings)
    yield


app = FastAPI(
    title="IDS Alert to MITRE ATT&CK Mapper",
    version="1.0.0",
    lifespan=lifespan,
)


def _authorize(x_api_key: str | None) -> None:
    if settings.api_key and x_api_key != settings.api_key:
        raise HTTPException(status_code=401, detail="Invalid or missing X-API-Key")


def _dependency_timeout() -> float:
    # Docker allows five seconds for the whole healthcheck. Run the three
    # probes concurrently and keep each one below that outer deadline.
    return min(settings.request_timeout, 3.0)


def _check_qdrant() -> dict[str, Any]:
    info = QdrantClient(
        settings.qdrant_url,
        settings.collection_name,
        _dependency_timeout(),
    ).collection_info()
    if not info:
        raise ServiceError(f"Collection {settings.collection_name} does not exist")

    result = info.get("result") if isinstance(info, dict) else None
    if not isinstance(result, dict):
        raise ServiceError("Qdrant returned an invalid collection response")

    collection_status = result.get("status")
    if collection_status == "red":
        raise ServiceError(f"Collection {settings.collection_name} is in red state")
    points_count = result.get("points_count")
    if not isinstance(points_count, int) or points_count <= 0:
        raise ServiceError(f"Collection {settings.collection_name} contains no indexed techniques")

    return {
        "status": collection_status or "available",
        "collection": settings.collection_name,
        "points_count": points_count,
    }


def _check_embedding() -> dict[str, Any]:
    probe_http(f"{settings.embedding_url}/health", _dependency_timeout())
    return {"status": "ok"}


def _check_reranker() -> dict[str, Any]:
    response = probe_http(f"{settings.reranker_url}/health", _dependency_timeout())
    if isinstance(response, dict) and response.get("status") not in (None, "ok"):
        raise ServiceError(f"Reranker is not ready: {response.get('status')}")
    return {
        "status": "ok",
        "model": response.get("model") if isinstance(response, dict) else None,
        "revision": response.get("revision") if isinstance(response, dict) else None,
    }


def _check_dependencies() -> tuple[dict[str, Any], dict[str, str]]:
    checks = {
        "qdrant": _check_qdrant,
        "embedding": _check_embedding,
        "reranker": _check_reranker,
    }
    healthy: dict[str, Any] = {}
    failures: dict[str, str] = {}

    with ThreadPoolExecutor(max_workers=len(checks)) as executor:
        futures = {executor.submit(check): name for name, check in checks.items()}
        for future in as_completed(futures):
            name = futures[future]
            try:
                healthy[name] = future.result()
            except Exception as exc:
                failures[name] = str(exc)[:500]

    return healthy, failures


@app.get("/health")
def health() -> JSONResponse:
    if pipeline is None:
        return JSONResponse(
            status_code=503,
            content={
                "status": "starting",
                "dependencies": {},
                "failures": {"mapper": "Mapping pipeline is not initialized"},
                "local_fallback": settings.local_fallback,
            },
        )

    dependencies, failures = _check_dependencies()
    return JSONResponse(
        status_code=503 if failures else 200,
        content={
            "status": "unhealthy" if failures else "ok",
            "dependencies": dependencies,
            "failures": failures,
            "local_fallback": settings.local_fallback,
        },
    )


@app.post("/map")
@app.post("/webhook/map")
def map_alert(payload: dict[str, Any], x_api_key: str | None = Header(default=None)) -> dict[str, Any]:
    _authorize(x_api_key)
    if pipeline is None:
        raise HTTPException(status_code=503, detail="Mapping pipeline is not ready")
    try:
        return pipeline.map_alert(payload)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Mapping pipeline failed: {exc}") from exc
