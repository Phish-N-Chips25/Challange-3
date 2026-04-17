"""
LLM/SLM inference router.

POST /infer/llm
    Body : BatchInferRequest
    Returns: LLMAlertResponse

Pipeline:
  1. Format Sysmon events as structured text
  2. Retrieve top-k ATT&CK techniques via ChromaDB RAG
  3. Call Phi-4 (or configured OLLAMA_MODEL) for attribution + explanation
  4. Return structured LLMAlertResponse
"""
from __future__ import annotations

import json
import logging
import re
import time

import requests
from fastapi import APIRouter, HTTPException

from api.models import BatchInferRequest, LLMAlertResponse
from config import (
    OLLAMA_BASE_URL, OLLAMA_MODEL, OLLAMA_TIMEOUT, RAG_TOP_K,
)
from data.attack_kb.vector_store import retrieve_hybrid

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/infer/llm", tags=["llm"])

_SKIP = {'', '-1', 'nan', 'None', '0', '-', 'N/A', 'n/a'}

_ATTRIBUTION_PROMPT = (
    "You are a cybersecurity analyst reviewing Windows Sysmon events flagged as anomalous.\n\n"
    "## Flagged Event Sequence\n"
    "{event_text}\n\n"
    "## Candidate ATT&CK Techniques (retrieved from knowledge base)\n"
    "{candidates_text}\n\n"
    "## Task\n"
    "Select the single best-matching ATT&CK technique for this event sequence.\n"
    "Return ONLY valid JSON with no markdown fences:\n"
    '{{"technique_id": "T1234.001", "technique_name": "...", '
    '"confidence": "high|medium|low", "explanation": "...", '
    '"recommended_action": "..."}}'
)


def _format_events(events: list[dict]) -> str:
    lines = []
    for i, ev in enumerate(events):
        parts = [f'Event {i+1}: EID={ev.get("EventID") or ev.get("event_id", "")}']
        for raw, canon in [
            ('Image', 'image'), ('CommandLine', 'command_line'),
            ('ParentImage', 'parent_image'), ('ParentCommandLine', 'parent_cmdline'),
            ('TargetObject', 'target_object'), ('TargetImage', 'target_image'),
            ('DestinationIp', 'dest_ip'), ('DestinationHostname', 'dest_hostname'),
            ('TargetFilename', 'target_filename'), ('QueryName', 'query_name'),
        ]:
            val = str(ev.get(raw) or ev.get(canon) or '').strip()
            if val and val not in _SKIP:
                parts.append(f'  {canon}: {val[:120]}')
        lines.append('\n'.join(parts))
    return '\n---\n'.join(lines)


def _ollama_chat(prompt: str) -> str:
    resp = requests.post(
        f'{OLLAMA_BASE_URL}/api/chat',
        json={
            'model': OLLAMA_MODEL,
            'messages': [{'role': 'user', 'content': prompt}],
            'stream': False,
            'options': {'temperature': 0.1},
        },
        timeout=OLLAMA_TIMEOUT,
    )
    resp.raise_for_status()
    return resp.json()['message']['content']


def _parse_json(text: str) -> dict:
    clean = re.sub(r'```(?:json)?\s*', '', text).strip().rstrip('`').strip()
    m = re.search(r'\{.*\}', clean, re.DOTALL)
    if m:
        return json.loads(m.group())
    raise ValueError(f'No JSON in LLM response: {text[:300]}')


@router.post("", response_model=LLMAlertResponse)
async def infer_llm(req: BatchInferRequest) -> LLMAlertResponse:
    """Attribute a window of Sysmon events to a MITRE ATT&CK technique via Phi-4."""
    t0 = time.perf_counter()
    events = [e.model_dump(exclude_none=False) for e in req.events]

    event_text = _format_events(events)

    # RAG retrieval
    try:
        hits = retrieve_hybrid(event_text[:500], k=RAG_TOP_K)
    except Exception as exc:
        logger.error("RAG retrieval failed: %s", exc)
        hits = []

    candidates_text = '\n'.join(
        f'[{h["technique_id"]}] {h["technique_name"]}: {h["document"][:300]}'
        for h in hits
    )

    prompt = _ATTRIBUTION_PROMPT.format(
        event_text=event_text[:1500],
        candidates_text=candidates_text,
    )

    # LLM call
    try:
        raw = _ollama_chat(prompt)
        attribution = _parse_json(raw)
    except requests.exceptions.ConnectionError:
        raise HTTPException(
            status_code=503,
            detail=f"Ollama not reachable at {OLLAMA_BASE_URL} — ensure it is running",
        )
    except Exception as exc:
        logger.error("LLM attribution failed: %s", exc)
        raise HTTPException(status_code=500, detail=f"LLM attribution failed: {exc}")

    latency_ms = (time.perf_counter() - t0) * 1000
    return LLMAlertResponse(
        window_size=len(events),
        anomaly_detected=True,
        techniques=[attribution.get('technique_id', '')],
        severity=attribution.get('confidence'),
        explanation=attribution.get('explanation'),
        recommended_action=attribution.get('recommended_action'),
        latency_ms=round(latency_ms, 2),
    )
