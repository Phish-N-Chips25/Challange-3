"""
chains.py — Process chain extraction for DualSentinel.

A `ProcessChain` groups events sharing the same `process_guid` (real or
synthesised by `schema.enforce_schema`). Chains preserve event order and
parent/child lineage, enabling chain-of-events evidence packs and
sequence-based detection — both inspired by `cyber-anomaly-detection`'s
`process_guid` chain workflow (see `notebooks/07_Sequence_Pipeline.ipynb`).

Design notes
------------
* Time-windowed `WindowFeatures` (preprocessor.make_windows) remain the
  coarse-grained scoring unit. Chains are an *additional* projection used
  for refinement of high-risk windows and for richer LLM evidence packs.
* `summarise_event(row)` is a single source of truth for event textification
  and is reused by the evidence pack builder.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterable, Iterator

import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)


# ── Chain dataclass ──────────────────────────────────────────────────────────

@dataclass
class ProcessChain:
    process_guid: str
    process_name: str = ""           # basename of the spawning image
    image: str = ""                  # full image path
    user: str = ""
    host: str = ""
    parent_guid: str = ""
    parent_process: str = ""
    parent_image: str = ""
    start: datetime | None = None
    end: datetime | None = None
    events: list[dict] = field(default_factory=list)   # ordered raw event dicts
    event_summaries: list[str] = field(default_factory=list)

    @property
    def length(self) -> int:
        return len(self.events)

    @property
    def duration_seconds(self) -> float:
        if self.start is None or self.end is None:
            return 0.0
        return float((self.end - self.start).total_seconds())

    @property
    def unique_event_ids(self) -> int:
        return len({e.get("event_id") for e in self.events})

    @property
    def child_count(self) -> int:
        """Number of distinct child processes spawned by this chain (EID 1)."""
        return len({
            e.get("target_process", "") for e in self.events
            if e.get("event_id") == 1 and e.get("target_process")
        })

    def to_dict(self) -> dict:
        return {
            "process_guid": self.process_guid,
            "process_name": self.process_name,
            "image": self.image,
            "user": self.user,
            "host": self.host,
            "parent_guid": self.parent_guid,
            "parent_process": self.parent_process,
            "parent_image": self.parent_image,
            "start": self.start.isoformat() if self.start else None,
            "end": self.end.isoformat() if self.end else None,
            "length": self.length,
            "duration_seconds": self.duration_seconds,
            "unique_event_ids": self.unique_event_ids,
            "child_count": self.child_count,
            "event_summaries": self.event_summaries,
        }


# ── Event textification (also used by evidence pack) ────────────────────────

def summarise_event(row: dict | pd.Series) -> str:
    """Return a single-line text summary of one event (≤ ~200 chars)."""
    get = row.get if isinstance(row, dict) else (lambda k, d="": row.get(k, d) if k in row else d)

    parts = [f"EID={get('event_id', 0)}"]
    pname = get("process_name", "")
    if pname:
        parts.append(f"proc={pname}")
    parent = get("parent_process", "")
    if parent:
        parts.append(f"parent={parent}")

    eid = get("event_id", 0)
    if eid == 3:  # network connection
        ip = get("network_dest_ip", "")
        port = get("network_dest_port", 0)
        if ip:
            parts.append(f"dst={ip}:{port}")
    if eid == 11:
        fp = get("file_path", "")
        if fp:
            parts.append(f"file={fp[:80]}")
    if eid in (12, 13, 14):
        rk = get("registry_key", "")
        if rk:
            parts.append(f"reg={rk[:80]}")
    if eid in (8, 10):
        ti = get("target_process", "") or get("target_image", "")
        if ti:
            parts.append(f"target={ti}")

    cmd = str(get("command_line", "") or "")
    if cmd and cmd != "nan":
        parts.append(f"cmd={cmd[:120]}")

    return " | ".join(parts).replace("```", "'''")


# ── Chain construction ──────────────────────────────────────────────────────

def make_chains(
    df: pd.DataFrame,
    *,
    min_length: int = 1,
    max_events_per_chain: int = 500,
) -> list[ProcessChain]:
    """
    Group events by `process_guid` and return ordered ProcessChain objects.

    * Requires `df` to conform to the canonical schema (see schema.py).
      `process_guid` is synthesised when missing, so chains always group
      consistently within (host, pid, day).
    * Chains shorter than `min_length` are filtered.
    * Each chain is capped at `max_events_per_chain` events to keep evidence
      packs bounded.
    """
    if df.empty or "process_guid" not in df.columns:
        return []

    df_sorted = df.sort_values(["process_guid", "timestamp"])
    chains: list[ProcessChain] = []

    for guid, group in df_sorted.groupby("process_guid", sort=False):
        if len(group) < min_length or not guid:
            continue

        head = group.iloc[0]
        chain = ProcessChain(
            process_guid=str(guid),
            process_name=str(head.get("process_name", "")),
            image=str(head.get("image", "")),
            user=str(head.get("user", "")),
            host=str(head.get("host", "")),
            parent_guid=str(head.get("parent_guid", "")),
            parent_process=str(head.get("parent_process", "")),
            parent_image=str(head.get("parent_image", "")),
            start=group["timestamp"].iloc[0].to_pydatetime(),
            end=group["timestamp"].iloc[-1].to_pydatetime(),
        )

        capped = group.head(max_events_per_chain)
        for row in capped.to_dict(orient="records"):
            chain.events.append(row)
            chain.event_summaries.append(summarise_event(row))

        chains.append(chain)

    # Sort chains by start time for stable downstream behaviour
    chains.sort(key=lambda c: c.start or datetime.min)
    logger.info(
        "Built %d chains (min_length=%d, max_events=%d) from %d events",
        len(chains), min_length, max_events_per_chain, len(df),
    )
    return chains


def chains_for_window(
    chains: Iterable[ProcessChain],
    window_start: datetime,
    window_end: datetime,
) -> list[ProcessChain]:
    """Return chains whose [start, end] overlaps [window_start, window_end)."""
    out = []
    for c in chains:
        if c.end is None or c.start is None:
            continue
        if c.end < window_start or c.start >= window_end:
            continue
        out.append(c)
    return out
