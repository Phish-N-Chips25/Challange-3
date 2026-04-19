"""
schema.py — Canonical event schema for DualSentinel.

Inspired by `cyber-anomaly-detection/data/schema.py`. All parsers
(`parse_csv`, `parse_evtx`, `parse_splunk_xml`) emit DataFrames that conform
to `CANONICAL_COLUMNS` after calling `enforce_schema()`. Existing DualSentinel
column names (`process_name`, `network_dest_ip`, ...) are kept to avoid
breaking the rest of the pipeline; this module only *adds* lineage and
provenance fields (process_guid, parent_guid, dataset_source, label,
technique, host, hashes).
"""

from __future__ import annotations

import hashlib
from typing import Iterable

import pandas as pd

# ── Canonical column order ───────────────────────────────────────────────────
CANONICAL_COLUMNS: list[str] = [
    # core
    "timestamp",          # tz-aware datetime (UTC)
    "event_id",           # int Sysmon EventID
    "host",               # source host / computer name
    "user",               # user account
    # process identity & lineage
    "process_guid",       # Sysmon ProcessGuid (synthesised if missing)
    "process_id",         # int
    "process_name",       # basename, lowercase
    "image",              # full image path (raw)
    "command_line",       # raw cmdline
    "parent_guid",        # Sysmon ParentProcessGuid
    "parent_id",          # int
    "parent_process",     # basename, lowercase
    "parent_image",       # full parent path
    # event payload
    "target_process",     # TargetImage basename
    "target_image",       # TargetImage full path
    "network_dest_ip",
    "network_dest_port",  # int
    "file_path",          # TargetFilename
    "registry_key",       # TargetObject
    "hashes",             # raw Hashes string
    # provenance & labels
    "dataset_source",     # 'lmd' | 'splunk' | 'silrad' | 'evtx' | 'otrf' | ...
    "label",              # int: -1 unknown, 0 normal, 1 malicious
    "technique",          # MITRE T-code or ""
]

INT_COLS: dict[str, str] = {
    "event_id":          "int32",
    "process_id":        "int64",
    "parent_id":         "int64",
    "network_dest_port": "int32",
    "label":             "int8",
}

STRING_COLS: list[str] = [c for c in CANONICAL_COLUMNS if c not in INT_COLS and c != "timestamp"]


def empty_frame() -> pd.DataFrame:
    """Return an empty DataFrame with the canonical schema."""
    return pd.DataFrame(columns=CANONICAL_COLUMNS)


def _synthesise_process_guid(row: pd.Series) -> str:
    """Deterministic fake ProcessGuid from (host, pid, process_name, day-floor of ts).

    Only used when the source dataset has no real ProcessGuid (e.g. LMD-2023).
    Same (host, pid, name, day) → same GUID, so chains group consistently
    within a single day even without real GUIDs.
    """
    ts = row.get("timestamp")
    day = ts.strftime("%Y%m%d") if pd.notna(ts) else ""
    key = f"{row.get('host', '')}|{row.get('process_id', 0)}|{row.get('process_name', '')}|{day}"
    h = hashlib.md5(key.encode("utf-8", errors="ignore")).hexdigest()
    # Format like a GUID for downstream tools that expect that shape.
    return f"{{{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}}}"


def enforce_schema(
    df: pd.DataFrame,
    *,
    dataset_source: str = "",
    synthesise_guids: bool = True,
) -> pd.DataFrame:
    """
    Add missing canonical columns with defaults, cast dtypes, and (optionally)
    synthesise process_guid / parent_guid for sources that lack them.

    Returns a NEW DataFrame with columns in `CANONICAL_COLUMNS` order.
    Does not drop rows; does not reorder rows.
    """
    df = df.copy()

    # Add missing columns with sensible defaults
    for col in CANONICAL_COLUMNS:
        if col not in df.columns:
            if col in INT_COLS:
                df[col] = -1 if col == "label" else 0
            elif col == "timestamp":
                df[col] = pd.NaT
            else:
                df[col] = ""

    # Stamp dataset_source if caller provided one (overrides any existing value)
    if dataset_source:
        df["dataset_source"] = dataset_source

    # Cast int cols
    for col, dtype in INT_COLS.items():
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(
            -1 if col == "label" else 0
        ).astype(dtype)

    # Cast string cols
    for col in STRING_COLS:
        df[col] = df[col].fillna("").astype(str)

    # Timestamp: ensure tz-aware UTC
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)

    # Synthesise process_guid where missing
    if synthesise_guids:
        empty_pguid = (df["process_guid"].astype(str).str.strip() == "")
        if empty_pguid.any():
            df.loc[empty_pguid, "process_guid"] = df.loc[empty_pguid].apply(
                _synthesise_process_guid, axis=1
            )

    # Reorder to canonical
    return df[CANONICAL_COLUMNS]


def normalise_basename(series: pd.Series) -> pd.Series:
    """Vectorised: lowercase basename of an image/path column."""
    return (
        series.astype(str)
        .str.replace("\\", "/", regex=False)
        .str.split("/").str[-1]
        .str.lower()
    )
