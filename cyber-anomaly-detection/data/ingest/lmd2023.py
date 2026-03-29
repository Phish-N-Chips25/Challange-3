"""
LMD-2023 dataset loader.

LMD-2023 contains raw Sysmon events (string fields) exported to CSV.
Notable columns: all Sysmon fields + 'Label' (0=Normal, 1=EoRS, 2=EoHT).
The labelled variant adds 'Label'; the preprocessed variant additionally
normalises some fields.

We map to the canonical schema defined in data/schema.py.

Because files are 1-1.5 GB, this loader always reads in chunks.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Iterator, Literal

import pandas as pd

from config import LMD_VARIANTS, LMD_DEFAULT_VARIANT
from data.schema import enforce_schema

logger = logging.getLogger(__name__)

# LMD label integers
LMD_LABEL_NORMAL = 0
LMD_LABEL_EORS   = 1   # End-of-Ransomware Session
LMD_LABEL_EOHT   = 2   # End-of-HardTarget (APT-like activity)

# Mapping from LMD raw column names → canonical schema fields
_COL_MAP = {
    "EventID":            "event_id",
    "UtcTime":            "utc_time",
    "ProcessGuid":        "process_guid",
    "ProcessId":          "process_id",
    "Image":              "image",
    "CommandLine":        "command_line",
    "CurrentDirectory":   "current_dir",
    "User":               "user",
    "IntegrityLevel":     "integrity_level",
    "ParentProcessGuid":  "parent_guid",
    "ParentProcessId":    "parent_id",
    "ParentImage":        "parent_image",
    "ParentCommandLine":  "parent_cmdline",
    "ImageLoaded":        "image_loaded",
    "Signed":             "signed",
    "Signature":          "signature",
    "SignatureStatus":    "sig_status",
    "TargetObject":       "target_object",
    "Details":            "details",
    "TargetImage":        "target_image",
    "GrantedAccess":      "granted_access",
    "CallTrace":          "call_trace",
    "DestinationIp":      "dest_ip",
    "DestinationPort":    "dest_port",
    "DestinationHostname":"dest_hostname",
    "TargetFilename":     "target_filename",
    "EventType":          "event_type",
    "PipeName":           "pipe_name",
    "QueryName":          "query_name",
    "QueryResults":       "query_results",
    "RuleName":           "rule_name",
    "Hashes":             "hashes",
    "Label":              "label",
}


def iter_chunks(
    variant: str = LMD_DEFAULT_VARIANT,
    kind: Literal["labelled", "preprocessed", "raw"] = "labelled",
    chunksize: int = 50_000,
    benign_only: bool = False,
) -> Iterator[pd.DataFrame]:
    """
    Yield canonical-schema DataFrames for the given LMD-2023 variant.

    Parameters
    ----------
    variant    : '1.75M' | '1.87M' | '2.3M'
    kind       : 'labelled' | 'preprocessed' | 'raw'
    chunksize  : rows per chunk
    benign_only: if True, filter to Label==0 within each chunk
    """
    path = Path(LMD_VARIANTS[variant][kind])
    if not path.exists():
        raise FileNotFoundError(f"LMD-2023 file not found: {path}")

    logger.info("Reading LMD-2023 %s (%s) in chunks of %d", variant, kind, chunksize)

    for chunk in pd.read_csv(path, chunksize=chunksize, low_memory=False, on_bad_lines="skip"):
        chunk = _remap(chunk)
        if benign_only and "label" in chunk.columns:
            chunk = chunk[chunk["label"] == LMD_LABEL_NORMAL]
        chunk["dataset_source"] = "LMD"
        yield enforce_schema(chunk)


def load_full(
    variant: str = LMD_DEFAULT_VARIANT,
    kind: Literal["labelled", "preprocessed"] = "labelled",
    max_rows: int | None = None,
) -> pd.DataFrame:
    """
    Load the entire dataset into memory (RAM-intensive for large variants).
    Use iter_chunks for production workflows.
    """
    frames: list[pd.DataFrame] = []
    rows = 0
    for df in iter_chunks(variant=variant, kind=kind):
        frames.append(df)
        rows += len(df)
        if max_rows is not None and rows >= max_rows:
            break
    return pd.concat(frames, ignore_index=True)


def _remap(df: pd.DataFrame) -> pd.DataFrame:
    """Rename raw LMD columns to canonical names."""
    rename = {k: v for k, v in _COL_MAP.items() if k in df.columns}
    return df.rename(columns=rename)
