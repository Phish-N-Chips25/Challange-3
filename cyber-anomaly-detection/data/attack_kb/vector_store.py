"""
ChromaDB-backed vector store for the ATT&CK knowledge base.

Workflow:
  1. build_kb() → list[KBEntry]          (data/attack_kb/builder.py)
  2. ingest(entries)                       → stores embeddings in ChromaDB
  3. retrieve(query, k)                    → top-k KBEntry strings for RAG

Embedding model: sentence-transformers all-MiniLM-L6-v2 (runs locally, ~80MB).
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Sequence

from config import CHROMA_PERSIST_DIR, EMBEDDING_MODEL, RAG_TOP_K

logger = logging.getLogger(__name__)

_COLLECTION_NAME = "attackkb"


def get_collection():
    """Return the ChromaDB collection (creates if missing)."""
    import chromadb
    from chromadb.utils import embedding_functions

    client = chromadb.PersistentClient(path=CHROMA_PERSIST_DIR)
    emb_fn = embedding_functions.SentenceTransformerEmbeddingFunction(
        model_name=EMBEDDING_MODEL
    )
    return client.get_or_create_collection(
        name=_COLLECTION_NAME,
        embedding_function=emb_fn,
        metadata={"hnsw:space": "cosine"},
    )


def ingest(entries, force: bool = False) -> None:
    """
    Embed and store KBEntry objects into ChromaDB.

    Parameters
    ----------
    entries : list[KBEntry]
    force   : if True, drop collection and re-ingest
    """
    import chromadb

    if force:
        client = chromadb.PersistentClient(path=CHROMA_PERSIST_DIR)
        try:
            client.delete_collection(_COLLECTION_NAME)
        except Exception:
            pass

    collection = get_collection()

    # Skip if already populated (and not forcing)
    if not force and collection.count() > 0:
        logger.info("ChromaDB collection already has %d docs, skipping ingest.", collection.count())
        return

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

    # ChromaDB add in batches of 500
    batch = 500
    for start in range(0, len(ids), batch):
        collection.add(
            ids=ids[start:start+batch],
            documents=documents[start:start+batch],
            metadatas=metadatas[start:start+batch],
        )
    logger.info("ChromaDB: ingested %d ATT&CK KB entries.", len(ids))


def retrieve(query: str, k: int = RAG_TOP_K) -> list[dict]:
    """
    Retrieve the top-k most relevant KB entries for a query string.

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


def setup_kb(force: bool = False) -> None:
    """
    Convenience function: build KB entries and ingest into ChromaDB.
    Safe to call multiple times (no-ops if already built).
    """
    from data.attack_kb.builder import build_kb
    entries = build_kb(force=force)
    ingest(entries, force=force)
    logger.info("ATT&CK KB ready: %d techniques indexed.", len(entries))
