"""Reproducibility + provenance smoke tests."""

import json
import random
from pathlib import Path

import numpy as np

from provenance import set_global_seed, sha256_file, Telemetry, write_run_manifest


def test_set_global_seed_makes_numpy_deterministic():
    set_global_seed(123)
    a = np.random.rand(5)
    set_global_seed(123)
    b = np.random.rand(5)
    assert np.allclose(a, b)


def test_set_global_seed_makes_random_deterministic():
    set_global_seed(7)
    a = [random.random() for _ in range(5)]
    set_global_seed(7)
    b = [random.random() for _ in range(5)]
    assert a == b


def test_sha256_file_stable(tmp_path: Path):
    p = tmp_path / "x.bin"
    p.write_bytes(b"hello dualsentinel")
    h1 = sha256_file(p)
    h2 = sha256_file(p)
    assert h1 == h2 and len(h1) == 64


def test_telemetry_summary_aggregates():
    t = Telemetry()
    t.record(stage="slm", model="phi3", duration_s=0.5,
             prompt_tokens=10, completion_tokens=5, ok=True)
    t.record(stage="slm", model="phi3", duration_s=1.5,
             prompt_tokens=20, completion_tokens=10, ok=False)
    t.record(stage="judge", model="llama3", duration_s=2.0,
             prompt_tokens=50, completion_tokens=25, ok=True)
    s = t.summary()
    assert s["total_calls"] == 3
    assert s["by_stage"]["slm"]["calls"] == 2
    assert s["by_stage"]["slm"]["errors"] == 1
    assert s["by_stage"]["slm"]["mean_duration_s"] == 1.0
    assert s["by_stage"]["judge"]["calls"] == 1


def test_run_manifest_has_required_keys(tmp_path: Path):
    inp = tmp_path / "in.csv"
    inp.write_bytes(b"event_id,timestamp\n1,2024-01-01T00:00:00Z\n")
    out = tmp_path / "out"
    out.mkdir()
    p = write_run_manifest(
        out, input_path=inp, dataset="lmd", threshold=0.6, seed=42,
        window_size_s=60, max_events=200, use_kb=True, skip_judge=False,
        max_llm_calls=20, n_windows=5, n_high_risk=2, n_judged=2,
        slm_model="phi3:mini", judge_model="llama3.2",
    )
    data = json.loads(p.read_text())
    for k in ("schema_version", "generated_at", "input", "config", "results", "telemetry"):
        assert k in data
    assert data["input"]["sha256"] == sha256_file(inp)
    assert data["config"]["seed"] == 42
