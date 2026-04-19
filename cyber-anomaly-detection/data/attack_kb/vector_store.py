"""
ChromaDB-backed vector store for the ATT&CK knowledge base.

Workflow:
  1. build_kb() → list[KBEntry]          (data/attack_kb/builder.py)
  2. ingest(entries)                       → stores embeddings in ChromaDB + BM25 index
  3. retrieve(query, k)                    → dense-only top-k (backward compat)
  4. retrieve_hybrid(query, k)             → RRF fusion of dense + BM25 (recommended)

Embedding model: configured via EMBEDDING_MODEL in config.py.
BM25 index:      persisted alongside ChromaDB as bm25_index.pkl.
"""
from __future__ import annotations

import logging
import pickle
import re
from pathlib import Path
from typing import Sequence

import numpy as np

from config import CHROMA_PERSIST_DIR, EMBEDDING_MODEL, RAG_TOP_K

logger = logging.getLogger(__name__)

_COLLECTION_NAME = "attackkb"
_BM25_FILENAME   = "bm25_index.pkl"


def _emb_device() -> str:
    """Return 'cuda' if a GPU is available *and* compatible with the installed
    PyTorch build, otherwise 'cpu'.

    Honours CHROMA_EMB_DEVICE env-var as an explicit override
    (e.g. CHROMA_EMB_DEVICE=cpu to force CPU).
    """
    import os
    override = os.getenv("CHROMA_EMB_DEVICE", "").strip().lower()
    if override in {"cpu", "cuda"}:
        logger.debug("Embedding device override: %s", override)
        return override
    try:
        import torch
        if not torch.cuda.is_available():
            return "cpu"
        # Verify the GPU's compute capability is supported by this torch build.
        # If the wheel was built for older sm_*, sm_120 (RTX 50xx) will fail at
        # kernel launch. Probe defensively.
        try:
            major, minor = torch.cuda.get_device_capability(0)
            supported = torch.cuda.get_arch_list()  # e.g. ['sm_50', ..., 'sm_90']
            tag = f"sm_{major}{minor}"
            if supported and tag not in supported and not any(
                int(s.removeprefix("sm_")) >= int(tag.removeprefix("sm_"))
                for s in supported if s.startswith("sm_")
            ):
                logger.warning(
                    "GPU compute capability %s not supported by torch (%s); "
                    "falling back to CPU. Override with CHROMA_EMB_DEVICE=cuda.",
                    tag, supported,
                )
                return "cpu"
        except Exception as e:  # noqa: BLE001
            logger.debug("CUDA capability probe failed: %s; falling back to CPU.", e)
            return "cpu"
        return "cuda"
    except ImportError:
        return "cpu"


# ── Tokeniser (shared by ingest and retrieval) ────────────────────────────────

def _tokenize(text: str) -> list[str]:
    """Lowercase alphanumeric tokenisation; keeps version numbers (e.g. v1.5)."""
    return re.findall(r'[a-z0-9]+(?:[._][a-z0-9]+)*', text.lower())


def _bm25_path() -> Path:
    return Path(CHROMA_PERSIST_DIR) / _BM25_FILENAME


# ── ChromaDB helpers ──────────────────────────────────────────────────────────

def get_collection():
    """Return the ChromaDB collection (creates if missing)."""
    import chromadb
    from chromadb.utils import embedding_functions

    client = chromadb.PersistentClient(path=CHROMA_PERSIST_DIR)
    emb_fn = embedding_functions.SentenceTransformerEmbeddingFunction(
        model_name=EMBEDDING_MODEL,
        device=_emb_device(),
    )
    return client.get_or_create_collection(
        name=_COLLECTION_NAME,
        embedding_function=emb_fn,
        metadata={"hnsw:space": "cosine"},
    )


# ── Ingest ────────────────────────────────────────────────────────────────────

def ingest(entries, force: bool = False) -> None:
    """
    Embed and store KBEntry objects into ChromaDB, and build a BM25 index.

    Parameters
    ----------
    entries : list[KBEntry]
    force   : if True, drop collection and rebuild from scratch
    """
    import chromadb
    from rank_bm25 import BM25Okapi

    if force:
        client = chromadb.PersistentClient(path=CHROMA_PERSIST_DIR)
        try:
            client.delete_collection(_COLLECTION_NAME)
        except Exception:
            pass

    collection = get_collection()

    if not force and collection.count() > 0:
        logger.info("ChromaDB collection already has %d docs, skipping ingest.", collection.count())
        # Still rebuild BM25 if it's missing
        if not _bm25_path().exists():
            _build_bm25_index(entries)
        return

    # ── ChromaDB ingest ────────────────────────────────────────────────────
    ids, documents, metadatas = [], [], []
    for i, entry in enumerate(entries):
        ids.append(f"{entry.source}_{entry.source_id}_{i}")
        documents.append(entry.description)
        metadatas.append({
            "technique_id":   entry.technique_id,
            "technique_name": entry.technique_name,
            "tactic_ids":     ",".join(entry.tactic_ids),
            "source":         entry.source,
            "keywords":       ",".join(entry.keywords),
        })

    batch = 500
    for start in range(0, len(ids), batch):
        collection.add(
            ids=ids[start:start+batch],
            documents=documents[start:start+batch],
            metadatas=metadatas[start:start+batch],
        )
    logger.info("ChromaDB: ingested %d ATT&CK KB entries.", len(ids))

    # ── BM25 index ─────────────────────────────────────────────────────────
    _build_bm25_index(entries)


def _build_bm25_index(entries) -> None:
    """Build and persist BM25Okapi index from KB entries."""
    from rank_bm25 import BM25Okapi

    documents = [e.description for e in entries]
    tokenized = [_tokenize(d) for d in documents]
    bm25      = BM25Okapi(tokenized)

    bm25_meta = [
        {
            "technique_id":   e.technique_id,
            "technique_name": e.technique_name,
            "document":       e.description,
            "tactic_ids":     ",".join(e.tactic_ids),
            "source":         e.source,
            "keywords":       ",".join(e.keywords),
        }
        for e in entries
    ]

    _bm25_path().write_bytes(pickle.dumps({"bm25": bm25, "meta": bm25_meta}))
    logger.info("BM25: index built for %d entries → %s", len(entries), _bm25_path())


# ── Retrieval ─────────────────────────────────────────────────────────────────

def retrieve(query: str, k: int = RAG_TOP_K) -> list[dict]:
    """
    Dense-only retrieval (ChromaDB cosine similarity).

    Returns a list of dicts with keys:
      document, technique_id, technique_name, tactic_ids, source, distance
    """
    collection = get_collection()
    if collection.count() == 0:
        logger.warning("ATT&CK KB is empty — run build_kb() and ingest() first.")
        return []

    results = collection.query(query_texts=[query], n_results=min(k, collection.count()))
    hits = []
    for doc, meta, dist in zip(
        results["documents"][0],
        results["metadatas"][0],
        results["distances"][0],
    ):
        hits.append({
            "document":       doc,
            "technique_id":   meta.get("technique_id", ""),
            "technique_name": meta.get("technique_name", ""),
            "tactic_ids":     meta.get("tactic_ids", "").split(","),
            "source":         meta.get("source", ""),
            "distance":       dist,
        })
    return hits


def retrieve_hybrid(query: str, k: int = RAG_TOP_K, rrf_k: int = 60) -> list[dict]:
    """
    Hybrid retrieval: dense (ChromaDB) + BM25, fused via Reciprocal Rank Fusion.

    Each source contributes  1 / (rrf_k + rank)  to a shared score.
    Results are deduplicated by (technique_id, document fingerprint) so multiple
    KB entries for the same technique can all contribute independently.

    Falls back to dense-only if BM25 index is not available.

    Parameters
    ----------
    query : free-text query (behavioral summary or raw event text)
    k     : number of results to return
    rrf_k : RRF constant (default 60, standard in literature)
    """
    # ── Dense candidates (retrieve 4× to give RRF enough to re-rank) ──────
    collection = get_collection()
    if collection.count() == 0:
        logger.warning("ATT&CK KB is empty — run ingest() first.")
        return []

    n_cand = min(k * 4, collection.count())
    dense_res = collection.query(query_texts=[query], n_results=n_cand)

    dense_hits = []
    for doc, meta, dist in zip(
        dense_res["documents"][0],
        dense_res["metadatas"][0],
        dense_res["distances"][0],
    ):
        dense_hits.append({
            "document":       doc,
            "technique_id":   meta.get("technique_id", ""),
            "technique_name": meta.get("technique_name", ""),
            "tactic_ids":     meta.get("tactic_ids", "").split(","),
            "source":         meta.get("source", ""),
            "distance":       dist,
        })

    # ── BM25 candidates ────────────────────────────────────────────────────
    bm25_hits: list[dict] = []
    if _bm25_path().exists():
        try:
            data     = pickle.loads(_bm25_path().read_bytes())
            bm25     = data["bm25"]
            bm25_meta = data["meta"]

            tokens = _tokenize(query)
            scores = bm25.get_scores(tokens)
            top_idx = np.argsort(scores)[::-1][:n_cand]

            for idx in top_idx:
                if scores[idx] <= 0:
                    break
                m = bm25_meta[idx]
                bm25_hits.append({
                    "document":       m["document"],
                    "technique_id":   m["technique_id"],
                    "technique_name": m["technique_name"],
                    "tactic_ids":     m["tactic_ids"].split(","),
                    "source":         m["source"],
                    "distance":       1.0 - scores[idx] / (scores[top_idx[0]] + 1e-9),
                })
        except Exception as exc:
            logger.warning("BM25 retrieval failed (%s); falling back to dense-only.", exc)
    else:
        logger.warning("BM25 index not found at %s; falling back to dense-only.", _bm25_path())

    # ── RRF fusion ─────────────────────────────────────────────────────────
    # Key: technique_id + first 80 chars of document (handles multiple docs per technique)
    rrf: dict[str, dict] = {}

    for rank, hit in enumerate(dense_hits):
        key = hit["technique_id"] + "||" + hit["document"][:80]
        if key not in rrf:
            rrf[key] = {"score": 0.0, "hit": hit}
        rrf[key]["score"] += 1.0 / (rrf_k + rank + 1)

    for rank, hit in enumerate(bm25_hits):
        key = hit["technique_id"] + "||" + hit["document"][:80]
        if key not in rrf:
            rrf[key] = {"score": 0.0, "hit": hit}
        rrf[key]["score"] += 1.0 / (rrf_k + rank + 1)

    sorted_hits = sorted(rrf.values(), key=lambda x: x["score"], reverse=True)
    return [r["hit"] for r in sorted_hits[:k]]


# ── Convenience ───────────────────────────────────────────────────────────────

def setup_kb(force: bool = False) -> None:
    """
    Convenience function: build KB entries and ingest into ChromaDB + BM25.
    Safe to call multiple times (no-ops if already built).
    """
    from data.attack_kb.builder import build_kb
    entries = build_kb(force=force)
    ingest(entries, force=force)
    logger.info("ATT&CK KB ready: %d techniques indexed.", len(entries))
