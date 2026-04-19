"""Regression tests for the schema-enforcement step.

The Sysmon CSVs we ingest have a habit of producing duplicate columns after
rename (e.g. LMD's `utctime` → `timestamp` collides with an existing field).
A single duplicate would crash `pd.to_numeric` with a 2D-frame error.
"""

import pandas as pd

from preprocessor import parse_csv  # noqa: F401  (smoke import)


def test_duplicate_columns_are_dropped(tmp_path):
    """If the source frame ends up with duplicates, enforce_schema must dedup."""
    from schema import enforce_schema

    df = pd.DataFrame({
        "event_id": [1, 4688, 4689],
        "timestamp": ["2024-01-01T00:00:00Z"] * 3,
        "process_name": ["a.exe", "b.exe", "c.exe"],
    })
    # Inject duplicate column intentionally.
    df["event_id_dup"] = df["event_id"]
    df = df.rename(columns={"event_id_dup": "event_id"})
    assert (df.columns == "event_id").sum() == 2
    out = enforce_schema(df)
    assert (out.columns == "event_id").sum() == 1
    assert len(out) == 3


def test_enforce_schema_idempotent():
    from schema import enforce_schema

    df = pd.DataFrame({
        "event_id":     [1, 2],
        "timestamp":    ["2024-01-01T00:00:00Z", "2024-01-01T00:00:01Z"],
        "process_name": ["a.exe", "b.exe"],
    })
    once = enforce_schema(df)
    twice = enforce_schema(once)
    assert list(once.columns) == list(twice.columns)
    assert len(once) == len(twice)
