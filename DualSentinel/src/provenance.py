"""
provenance.py — Reproducibility, telemetry and run manifest helpers.

What an ISEP examiner expects from a research/engineering pipeline:
  - Determinism: a single `--seed` knob propagates to numpy + python random
    + PYTHONHASHSEED + (optional) torch.
  - Provenance: every artefact directory contains a `run_manifest.json`
    that pins the input file (sha256), the models, the threshold, the git
    commit, the wall time and the total number of LLM calls.
  - Telemetry: a `Telemetry` recorder collects per-call latency and token
    counts and persists `telemetry.json` so cost/throughput claims are
    auditable.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import random
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import numpy as np


# ── Deterministic seeding ────────────────────────────────────────────────

def set_global_seed(seed: int = 42) -> None:
    """Seed every RNG that the pipeline can transitively reach."""
    os.environ["PYTHONHASHSEED"] = str(seed)
    random.seed(seed)
    np.random.seed(seed)
    try:
        import torch  # type: ignore
        torch.manual_seed(seed)
        if torch.cuda.is_available():
            torch.cuda.manual_seed_all(seed)
    except Exception:
        pass


# ── File hashing ─────────────────────────────────────────────────────────

def sha256_file(path: Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(chunk), b""):
            h.update(block)
    return h.hexdigest()


# ── Git commit (best-effort, no failure if not a repo) ───────────────────

def git_commit() -> Optional[str]:
    try:
        out = subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            stderr=subprocess.DEVNULL, timeout=2,
        )
        return out.decode().strip()
    except Exception:
        return None


# ── Telemetry ────────────────────────────────────────────────────────────

@dataclass
class CallRecord:
    stage: str            # "slm" | "judge"
    model: str
    duration_s: float
    prompt_tokens: int = 0
    completion_tokens: int = 0
    ok: bool = True
    error: str = ""


@dataclass
class Telemetry:
    """Lightweight recorder for Ollama/LLM calls."""
    started_at: float = field(default_factory=time.time)
    records: list[CallRecord] = field(default_factory=list)

    def record(self, *, stage: str, model: str, duration_s: float,
               prompt_tokens: int = 0, completion_tokens: int = 0,
               ok: bool = True, error: str = "") -> None:
        self.records.append(CallRecord(
            stage=stage, model=model, duration_s=duration_s,
            prompt_tokens=prompt_tokens, completion_tokens=completion_tokens,
            ok=ok, error=error,
        ))

    def summary(self) -> dict:
        by_stage: dict = {}
        for r in self.records:
            s = by_stage.setdefault(r.stage, {
                "calls": 0, "ok": 0, "errors": 0,
                "total_duration_s": 0.0, "prompt_tokens": 0, "completion_tokens": 0,
            })
            s["calls"] += 1
            s["ok"] += int(r.ok)
            s["errors"] += int(not r.ok)
            s["total_duration_s"] += r.duration_s
            s["prompt_tokens"] += r.prompt_tokens
            s["completion_tokens"] += r.completion_tokens
        for s in by_stage.values():
            s["mean_duration_s"] = s["total_duration_s"] / max(s["calls"], 1)
        return {
            "wall_time_s": time.time() - self.started_at,
            "total_calls": len(self.records),
            "by_stage": by_stage,
        }

    def dump(self, path: Path) -> None:
        path.write_text(json.dumps({
            "summary": self.summary(),
            "records": [r.__dict__ for r in self.records],
        }, indent=2), encoding="utf-8")


# Module-level singleton (importing modules can `from provenance import TELEMETRY`).
TELEMETRY = Telemetry()


# ── Run manifest ─────────────────────────────────────────────────────────

def write_run_manifest(
    output_dir: Path,
    *,
    input_path: Path,
    dataset: str,
    threshold: float,
    seed: int,
    window_size_s: int,
    max_events: int,
    use_kb: bool,
    skip_judge: bool,
    max_llm_calls: Optional[int],
    n_windows: int,
    n_high_risk: int,
    n_judged: int,
    slm_model: str,
    judge_model: str,
    extra: Optional[dict] = None,
) -> Path:
    manifest = {
        "schema_version": 1,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "git_commit": git_commit(),
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "input": {
            "path": str(input_path),
            "size_bytes": input_path.stat().st_size if input_path.exists() else None,
            "sha256": sha256_file(input_path) if input_path.exists() else None,
            "dataset": dataset,
        },
        "config": {
            "seed": seed,
            "anomaly_threshold": threshold,
            "window_size_s": window_size_s,
            "max_events_per_window": max_events,
            "use_kb": use_kb,
            "skip_judge": skip_judge,
            "max_llm_calls": max_llm_calls,
            "slm_model": slm_model,
            "judge_model": judge_model,
        },
        "results": {
            "n_windows": n_windows,
            "n_high_risk": n_high_risk,
            "n_judged": n_judged,
        },
        "telemetry": TELEMETRY.summary(),
    }
    if extra:
        manifest["extra"] = extra

    path = output_dir / "run_manifest.json"
    path.write_text(json.dumps(manifest, indent=2, default=str), encoding="utf-8")
    return path
