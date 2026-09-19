from __future__ import annotations

import math
import os
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel, Field
from sentence_transformers import CrossEncoder


MODEL_ID = os.getenv("RERANKER_MODEL", "cross-encoder/ms-marco-MiniLM-L-6-v2")
MODEL_REVISION = os.getenv("RERANKER_REVISION", "c5ee24cb16019beea0893ab7796b1df96625c6b8")
model: CrossEncoder | None = None


class RerankRequest(BaseModel):
    query: str = Field(min_length=1)
    texts: list[str] = Field(min_length=1, max_length=30)
    raw_scores: bool = False


@asynccontextmanager
async def lifespan(_: FastAPI):
    global model
    model = CrossEncoder(MODEL_ID, revision=MODEL_REVISION, max_length=512)
    yield


app = FastAPI(title="MITRE Cross-Encoder Reranker", version="1.0.0", lifespan=lifespan)


@app.get("/health")
def health() -> dict[str, Any]:
    return {"status": "ok" if model else "starting", "model": MODEL_ID, "revision": MODEL_REVISION}


@app.post("/rerank")
def rerank(body: RerankRequest) -> dict[str, Any]:
    if model is None:
        raise RuntimeError("Model is not loaded")
    raw = model.predict([(body.query, text) for text in body.texts], show_progress_bar=False)
    rows = []
    for index, value in enumerate(raw):
        raw_score = float(value)
        score = raw_score if body.raw_scores else 1.0 / (1.0 + math.exp(-max(-60.0, min(60.0, raw_score))))
        rows.append({"index": index, "score": score, "raw_score": raw_score})
    rows.sort(key=lambda row: (-row["score"], row["index"]))
    return {"model": MODEL_ID, "revision": MODEL_REVISION, "results": rows}
