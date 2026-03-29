"""
SILRAD dataset loader.

The SILRAD CSVs contain FastText-embedded numeric features, not raw strings.
Columns: event.code, <Sysmon fields as floats>, task, class (0=benign, 1=ransomware)

This loader returns:
  - X  (np.ndarray, float32) — all feature columns except 'class'
  - y  (np.ndarray, int8)    — 'class' column
  - feature_names (list[str])
"""
from __future__ import annotations

import numpy as np
import pandas as pd
from pathlib import Path
from typing import Literal

from config import SILRAD_TRAIN, SILRAD_TEST, SILRAD_ALL


# The label column name in SILRAD
_LABEL_COL = "class"


def load(
    split: Literal["train", "test", "all"] = "all",
    path: Path | None = None,
    chunksize: int | None = None,
) -> tuple[np.ndarray, np.ndarray, list[str]]:
    """
    Load a SILRAD split.

    Parameters
    ----------
    split    : 'train' | 'test' | 'all'
    path     : Override default path if provided.
    chunksize: If set, returns an iterator of (X_chunk, y_chunk, feature_names).

    Returns
    -------
    X             : float32 array of shape (n_events, n_features)
    y             : int8 array of shape (n_events,)
    feature_names : list of column names used as features
    """
    if path is None:
        path = {"train": SILRAD_TRAIN, "test": SILRAD_TEST, "all": SILRAD_ALL}[split]

    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"SILRAD file not found: {path}")

    if chunksize is not None:
        return _chunked_loader(path, chunksize)

    df = pd.read_csv(path, low_memory=False)
    return _split_xy(df)


def _split_xy(df: pd.DataFrame) -> tuple[np.ndarray, np.ndarray, list[str]]:
    y_raw = df[_LABEL_COL].values.astype(np.int8)
    feature_cols = [c for c in df.columns if c != _LABEL_COL]
    X = df[feature_cols].values.astype(np.float32)
    return X, y_raw, feature_cols


def _chunked_loader(path: Path, chunksize: int):
    """Yield (X, y, feature_names) tuples for each chunk."""
    feature_names: list[str] | None = None
    for chunk in pd.read_csv(path, chunksize=chunksize, low_memory=False):
        X, y, names = _split_xy(chunk)
        if feature_names is None:
            feature_names = names
        yield X, y, names


def benign_only(split: Literal["train", "all"] = "train") -> tuple[np.ndarray, list[str]]:
    """Return only benign (label=0) samples — used for self-supervised training."""
    X, y, feat = load(split)
    mask = y == 0
    return X[mask], feat
