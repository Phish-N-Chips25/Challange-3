"""
attack_kb.py — Thin retrieval wrapper around the cyber-anomaly-detection
ATT&CK knowledge base (ChromaDB + optional BM25, with RRF fusion).

This module reuses the already-indexed Chroma collection at
`cyber-anomaly-detection/data/attack_kb/chroma_db/` instead of duplicating
the KB. Imports the upstream `vector_store` module on demand via a sys.path
shim so DualSentinel doesn't take a hard dependency on the sibling project's
package layout.

Usage
-----
    from attack_kb import retrieve_for_window, retrieve

    hits = retrieve_for_window(window_dict, k=5)
    # → [{technique_id, technique_name, document, source, distance}, ...]

If the upstream KB is unavailable (missing folder, missing chromadb, GPU
issues, etc.) all functions return [] and log a one-time warning so the
caller can fall back to the rule-based tagger without crashing.
"""

from __future__ import annotations

import logging
import os
import sys
from functools import lru_cache
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# ── Locate the cyber-anomaly-detection project ──────────────────────────────

_DEFAULT_CYBER_ROOT = (
    Path(__file__).resolve().parent.parent.parent / "cyber-anomaly-detection"
)
CYBER_ROOT = Path(os.getenv("CYBER_ANOMALY_ROOT", _DEFAULT_CYBER_ROOT)).resolve()

# Force CPU embeddings by default — DualSentinel runs on the same machine as
# the SLM/LLM and we don't want to fight Ollama for VRAM. Caller can override
# with CHROMA_EMB_DEVICE=cuda.
os.environ.setdefault("CHROMA_EMB_DEVICE", "cpu")


@lru_cache(maxsize=1)
def _load_vector_store():
    """Lazy import of cyber-anomaly-detection's vector_store. Cached."""
    if not CYBER_ROOT.exists():
        logger.warning(
            "ATT&CK KB unavailable: %s does not exist. "
            "Set CYBER_ANOMALY_ROOT env var to point at it.",
            CYBER_ROOT,
        )
        return None

    if str(CYBER_ROOT) not in sys.path:
        sys.path.insert(0, str(CYBER_ROOT))

    try:
        # vector_store imports `config` and `data.attack_kb.builder` from the
        # cyber-anomaly-detection package, so we need its root on sys.path.
        from data.attack_kb import vector_store  # type: ignore
        return vector_store
    except Exception as exc:  # noqa: BLE001
        logger.warning("Failed to import cyber-anomaly KB (%s) — KB retrieval disabled.", exc)
        return None


# ── Public retrieval API ────────────────────────────────────────────────────

def is_available() -> bool:
    """True iff the KB can be queried (chroma + ingested entries)."""
    vs = _load_vector_store()
    if vs is None:
        return False
    try:
        return vs.get_collection().count() > 0
    except Exception as exc:  # noqa: BLE001
        logger.debug("KB availability check failed: %s", exc)
        return False


def retrieve(query: str, k: int = 5) -> list[dict]:
    """
    Retrieve top-k ATT&CK candidates for a free-text query.

    Uses hybrid (dense + BM25 RRF) retrieval when BM25 index is present;
    falls back to dense-only otherwise. Returns [] if KB unavailable.
    """
    vs = _load_vector_store()
    if vs is None:
        return []
    try:
        return vs.retrieve_hybrid(query, k=k)
    except Exception as exc:  # noqa: BLE001
        logger.debug("KB retrieve_hybrid failed (%s); trying dense-only.", exc)
        try:
            return vs.retrieve(query, k=k)
        except Exception as exc2:  # noqa: BLE001
            logger.warning("KB retrieve failed: %s", exc2)
            return []


# ── Window-aware query builder ──────────────────────────────────────────────

# Behavioural anchors: short phrases that map cleanly to ATT&CK descriptions.
# Triggered by aggregate counters in the window dict.
_BEHAVIOUR_ANCHORS: list[tuple[str, callable]] = [
    ("PowerShell encoded command execution",
     lambda w: w.get("powershell_count", 0) > 0),
    ("Windows command shell execution cmd.exe",
     lambda w: w.get("cmd_count", 0) > 0),
    ("SMB Windows admin shares lateral movement port 445",
     lambda w: w.get("lateral_movement_port_count", 0) > 0),
    ("Registry run key persistence autostart",
     lambda w: w.get("registry_modification_count", 0) > 3),
    ("LSASS process access credential dumping",
     lambda w: w.get("process_access_count", 0) > 0),
    ("CreateRemoteThread process injection",
     lambda w: w.get("remote_thread_count", 0) > 0),
    ("Driver loaded kernel rootkit",
     lambda w: w.get("driver_load_count", 0) > 0),
    ("Mass file deletion data destruction wiper",
     lambda w: w.get("file_delete_count", 0) > 10),
    ("Mass file creation ransomware encryption",
     lambda w: w.get("file_creation_count", 0) > 50),
    ("Outbound C2 application layer protocol command and control",
     lambda w: w.get("outbound_unique_ips", 0) > 10),
    ("Mimikatz credential extraction",
     lambda w: w.get("has_mimikatz", False)),
    ("PsExec remote service execution",
     lambda w: w.get("has_psexec", False)),
]


def build_window_queries(window: dict, max_queries: int = 4) -> list[str]:
    """
    Translate a window dict into a small set of natural-language queries that
    play well with sentence-transformer embeddings of ATT&CK descriptions.
    """
    triggered = [phrase for phrase, cond in _BEHAVIOUR_ANCHORS
                 if _safe_call(cond, window)]
    queries: list[str] = list(dict.fromkeys(triggered))[:max_queries]

    # Always include a generic summary as a fallback / context query.
    summary = _summary_query(window)
    if summary and summary not in queries:
        queries.append(summary)

    return queries


def _safe_call(fn, w) -> bool:
    try:
        return bool(fn(w))
    except Exception:  # noqa: BLE001
        return False


def _summary_query(window: dict) -> str:
    bits: list[str] = []
    if window.get("process_creation_count", 0):
        bits.append(f"{window['process_creation_count']} process creations")
    if window.get("network_connection_count", 0):
        bits.append(f"{window['network_connection_count']} network connections")
    if window.get("registry_modification_count", 0):
        bits.append(f"{window['registry_modification_count']} registry mods")
    if window.get("file_creation_count", 0):
        bits.append(f"{window['file_creation_count']} file creations")
    return ", ".join(bits) if bits else ""


def retrieve_for_window(window: dict, k: int = 5) -> list[dict]:
    """
    Retrieve ATT&CK candidates for a single window, deduplicated by
    technique_id, with `score` derived from RRF ranking across queries.

    Returns at most `k` hits, sorted by combined score descending.
    """
    queries = build_window_queries(window)
    if not queries:
        return []

    pool: dict[str, dict] = {}
    rrf_k = 60
    for qi, q in enumerate(queries):
        hits = retrieve(q, k=k)
        for rank, h in enumerate(hits):
            tid = h.get("technique_id") or h.get("document", "")[:32]
            entry = pool.get(tid)
            if entry is None:
                pool[tid] = {
                    "technique_id":   h.get("technique_id", ""),
                    "technique_name": h.get("technique_name", ""),
                    "document":       h.get("document", ""),
                    "source":         h.get("source", ""),
                    "score":          0.0,
                    "matched_queries": [],
                }
                entry = pool[tid]
            entry["score"] += 1.0 / (rrf_k + rank + 1)
            entry["matched_queries"].append(q)

    ranked = sorted(pool.values(), key=lambda x: x["score"], reverse=True)
    return ranked[:k]
