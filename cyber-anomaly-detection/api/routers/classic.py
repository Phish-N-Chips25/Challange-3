"""
Classic pipeline inference router.

POST /infer/classic
    Body : BatchInferRequest
    Returns: ClassicAlertResponse

TODO: Wire up the trained models from notebooks/checkpoints/:
  - word2vec feature pipeline  → checkpoints/word2vec/
  - tfidf_svd feature pipeline → checkpoints/tfidf_svd/
  - single-event AE            → checkpoints/models/autoencoder/
  - sequence AE                → checkpoints/models/seq/seq_ae_word2vec.pt
"""
from __future__ import annotations

import logging
import time
from typing import Any

import pandas as pd
from fastapi import APIRouter, HTTPException

from api.models import BatchInferRequest, ClassicAlertResponse

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/infer/classic", tags=["classic"])


def _get_models() -> dict[str, Any]:
    # TODO: load fitted pipelines and model weights from checkpoints/
    return {}


@router.post("", response_model=ClassicAlertResponse)
async def infer_classic(req: BatchInferRequest) -> ClassicAlertResponse:
    """Run the anomaly detection pipeline on a window of Sysmon events."""
    t0 = time.perf_counter()
    df = pd.DataFrame([e.model_dump(exclude_none=False) for e in req.events])

    models = _get_models()
    if not models:
        latency_ms = (time.perf_counter() - t0) * 1000
        return ClassicAlertResponse(
            window_size=len(df),
            anomaly_score=0.0,
            is_anomaly=False,
            techniques=[],
            latency_ms=round(latency_ms, 2),
        )

    raise HTTPException(status_code=501, detail="Inference not yet implemented.")
