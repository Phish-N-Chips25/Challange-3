"""
FastAPI application entry point.

Startup initialises both pipeline model caches, mounts both routers,
and exposes a /health endpoint.

Run locally:
    uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.models import HealthResponse
from api.routers import classic, llm

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Pre-warm model cache at startup so the first request is fast."""
    try:
        classic._get_models()
        logger.info("API ready.")
    except Exception as exc:
        logger.warning("Model warm-up skipped: %s", exc)
    yield


app = FastAPI(
    title="Cyber Anomaly Detection API",
    description=(
        "Dual-pipeline Sysmon anomaly detection: "
        "Classical (IForest + GRU/Transformer) vs LLM/SLM (Ollama + RAG + Judge)"
    ),
    version="0.1.0",
    lifespan=lifespan,
)

# Allow all origins for development; restrict in production via env variable
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers
app.include_router(classic.router)
app.include_router(llm.router)


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

@app.get("/health", response_model=HealthResponse, tags=["ops"])
async def health() -> HealthResponse:
    """Return readiness status of the detection pipeline."""
    models_ready = bool(classic._get_models())
    return HealthResponse(
        status="ok",
        classic_ready=models_ready,
        llm_ready=False,
        kafka_ready=False,
    )
