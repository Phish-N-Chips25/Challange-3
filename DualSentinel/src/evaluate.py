"""
evaluate.py — Window-level + technique-level evaluation metrics.

Inputs (all already produced by pipeline.run_pipeline):
- windows_scored.json — each window has `label` (0/1/-1) and `detector_score`
- judge_results.json  — per-window verdict + ATT&CK technique claims
- (optional) `techniques_truth` per window for technique-level evaluation

Outputs:
- console table (rich)
- metrics.json saved alongside other artefacts

Metrics computed (only on windows where label != -1):

Window-level (binary: malicious vs normal)
- counts (TP/FP/TN/FN), precision, recall, F1, accuracy, FPR
- ROC-AUC + PR-AUC over `detector_score`
- Same trio for the LLM judge (anomaly_score / 10 normalised) when available
- Confusion matrix at the chosen threshold

Technique-level (multi-label, per ATT&CK ID)
- micro / macro precision-recall-F1 of judge.techniques vs window.techniques_truth
- only computed when at least one window has a non-empty techniques_truth
"""

from __future__ import annotations

import json
import logging
from collections import Counter
from pathlib import Path
from typing import Optional

import numpy as np
from rich.console import Console
from rich.table import Table

logger = logging.getLogger(__name__)
console = Console()


# ── Pure metric helpers (no sklearn dependency for the basic ones) ────────

def _confusion(y_true: np.ndarray, y_pred: np.ndarray) -> dict:
    tp = int(((y_pred == 1) & (y_true == 1)).sum())
    tn = int(((y_pred == 0) & (y_true == 0)).sum())
    fp = int(((y_pred == 1) & (y_true == 0)).sum())
    fn = int(((y_pred == 0) & (y_true == 1)).sum())
    return {"tp": tp, "tn": tn, "fp": fp, "fn": fn}


def _prf1(cm: dict) -> dict:
    tp, fp, fn, tn = cm["tp"], cm["fp"], cm["fn"], cm["tn"]
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec  = tp / (tp + fn) if (tp + fn) else 0.0
    f1   = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    acc  = (tp + tn) / max(tp + tn + fp + fn, 1)
    fpr  = fp / (fp + tn) if (fp + tn) else 0.0
    return {"precision": prec, "recall": rec, "f1": f1, "accuracy": acc, "fpr": fpr}


def _roc_auc(y_true: np.ndarray, scores: np.ndarray) -> Optional[float]:
    """ROC-AUC via the rank/Mann-Whitney-U identity. Returns None if
    only one class is present in y_true."""
    pos = scores[y_true == 1]
    neg = scores[y_true == 0]
    if len(pos) == 0 or len(neg) == 0:
        return None
    # Tie-aware AUC via average ranks
    order = np.argsort(np.concatenate([pos, neg]), kind="mergesort")
    ranks = np.empty_like(order, dtype=float)
    ranks[order] = np.arange(1, len(order) + 1)
    pos_rank_sum = ranks[: len(pos)].sum()
    auc = (pos_rank_sum - len(pos) * (len(pos) + 1) / 2) / (len(pos) * len(neg))
    return float(auc)


def _pr_auc(y_true: np.ndarray, scores: np.ndarray) -> Optional[float]:
    """Average-precision (area under the precision-recall curve)."""
    if (y_true == 1).sum() == 0:
        return None
    order = np.argsort(-scores, kind="mergesort")
    y_sorted = y_true[order]
    tp_cum = np.cumsum(y_sorted == 1)
    fp_cum = np.cumsum(y_sorted == 0)
    recall = tp_cum / max((y_true == 1).sum(), 1)
    precision = tp_cum / np.maximum(tp_cum + fp_cum, 1)
    # AP = sum of (recall_i - recall_{i-1}) * precision_i
    recall_prev = np.concatenate([[0.0], recall[:-1]])
    ap = float(np.sum((recall - recall_prev) * precision))
    return ap


def _multilabel_pr_f1(
    y_true_lists: list[list[str]],
    y_pred_lists: list[list[str]],
) -> dict:
    """Micro + macro precision/recall/F1 for multi-label ATT&CK techniques."""
    all_labels = sorted({t for s in (y_true_lists + y_pred_lists) for t in s})
    if not all_labels:
        return {}
    micro = {"tp": 0, "fp": 0, "fn": 0}
    per_label = {l: {"tp": 0, "fp": 0, "fn": 0} for l in all_labels}
    for truth, pred in zip(y_true_lists, y_pred_lists):
        t_set, p_set = set(truth), set(pred)
        for l in all_labels:
            in_t, in_p = l in t_set, l in p_set
            if in_t and in_p:
                per_label[l]["tp"] += 1; micro["tp"] += 1
            elif in_p and not in_t:
                per_label[l]["fp"] += 1; micro["fp"] += 1
            elif in_t and not in_p:
                per_label[l]["fn"] += 1; micro["fn"] += 1
    micro_prf = _prf1({**micro, "tn": 0})
    macro_p = np.mean([_prf1({**v, "tn": 0})["precision"] for v in per_label.values()])
    macro_r = np.mean([_prf1({**v, "tn": 0})["recall"]    for v in per_label.values()])
    macro_f1 = 2 * macro_p * macro_r / (macro_p + macro_r) if (macro_p + macro_r) else 0.0
    return {
        "n_labels": len(all_labels),
        "micro": {k: micro_prf[k] for k in ("precision", "recall", "f1")},
        "macro": {"precision": float(macro_p), "recall": float(macro_r), "f1": float(macro_f1)},
        "per_label": {l: _prf1({**v, "tn": 0}) for l, v in per_label.items()},
    }


# ── Public entry point ───────────────────────────────────────────────────

def evaluate_run(
    windows: list[dict],
    judge_results: Optional[list[dict]] = None,
    threshold: float = 0.6,
    output_path: Optional[Path] = None,
) -> dict:
    """Compute metrics; optionally persist as `metrics.json`."""
    judge_results = judge_results or []
    judge_by_start = {r.get("window_start"): r for r in judge_results}

    # Drop unlabelled windows
    labelled = [w for w in windows if int(w.get("label", -1)) in (0, 1)]
    if not labelled:
        console.print("[yellow]No labelled windows — skipping metrics.[/yellow]")
        return {"n_windows": len(windows), "n_labelled": 0}

    y_true = np.array([int(w["label"]) for w in labelled], dtype=int)
    det_scores = np.array([float(w.get("detector_score", 0.0)) for w in labelled])

    metrics: dict = {
        "n_windows": len(windows),
        "n_labelled": len(labelled),
        "n_positive": int((y_true == 1).sum()),
        "n_negative": int((y_true == 0).sum()),
        "threshold": threshold,
        "detector": {},
    }

    # ── Detector (1st sentinel) ───────────────────────────────────────
    det_pred = (det_scores >= threshold).astype(int)
    det_cm   = _confusion(y_true, det_pred)
    metrics["detector"] = {
        "confusion": det_cm,
        **_prf1(det_cm),
        "roc_auc": _roc_auc(y_true, det_scores),
        "pr_auc":  _pr_auc(y_true, det_scores),
    }

    # ── Judge (2nd sentinel) — only on labelled & judged windows ──────
    judged_idx = [i for i, w in enumerate(labelled) if w["window_start"] in judge_by_start]
    if judged_idx:
        y_true_j = y_true[judged_idx]
        judge_pred = np.array([
            1 if judge_by_start[labelled[i]["window_start"]]["verdict"] in ("malicious", "suspicious") else 0
            for i in judged_idx
        ])
        judge_score = np.array([
            float(judge_by_start[labelled[i]["window_start"]].get("anomaly_score", 0)) / 10.0
            for i in judged_idx
        ])
        j_cm = _confusion(y_true_j, judge_pred)
        metrics["judge"] = {
            "n_evaluated": len(judged_idx),
            "confusion": j_cm,
            **_prf1(j_cm),
            "roc_auc": _roc_auc(y_true_j, judge_score),
            "pr_auc":  _pr_auc(y_true_j, judge_score),
        }

    # ── Technique-level (multi-label) ─────────────────────────────────
    truth_lists = [list(w.get("techniques_truth", [])) for w in labelled if w.get("techniques_truth")]
    if truth_lists:
        pred_lists = []
        for w in labelled:
            if not w.get("techniques_truth"):
                continue
            jr = judge_by_start.get(w["window_start"])
            tids = []
            if jr:
                for t in jr.get("techniques", []):
                    tid = (t.get("technique_id") or "").strip()
                    if tid:
                        tids.append(tid)
            pred_lists.append(sorted(set(tids)))
        metrics["techniques"] = _multilabel_pr_f1(truth_lists, pred_lists)

    # ── Render + persist ──────────────────────────────────────────────
    _print_metrics_table(metrics)
    if output_path is not None:
        output_path.write_text(json.dumps(metrics, indent=2, default=str), encoding="utf-8")
        console.print(f"  [dim]→ {output_path}[/dim]")
    return metrics


def _print_metrics_table(m: dict) -> None:
    n_lbl, n_pos, n_neg = m["n_labelled"], m["n_positive"], m["n_negative"]
    console.print(
        f"\n[bold]Evaluated:[/bold] {n_lbl} labelled windows  "
        f"(pos={n_pos}, neg={n_neg}, threshold={m['threshold']})"
    )

    for name in ("detector", "judge"):
        if name not in m:
            continue
        d = m[name]
        cm = d["confusion"]
        tbl = Table(title=f"{name.capitalize()} (window-level)", show_header=True)
        tbl.add_column("metric", style="cyan")
        tbl.add_column("value", justify="right")
        for key in ("precision", "recall", "f1", "accuracy", "fpr"):
            tbl.add_row(key, f"{d[key]:.4f}")
        for key in ("roc_auc", "pr_auc"):
            v = d.get(key)
            tbl.add_row(key, f"{v:.4f}" if v is not None else "n/a")
        tbl.add_row("TP / FP / FN / TN", f"{cm['tp']} / {cm['fp']} / {cm['fn']} / {cm['tn']}")
        console.print(tbl)

    if "techniques" in m and m["techniques"]:
        t = m["techniques"]
        tbl = Table(title=f"Techniques (multi-label, n={t['n_labels']} unique IDs)", show_header=True)
        tbl.add_column("avg", style="cyan")
        for h in ("precision", "recall", "f1"):
            tbl.add_column(h, justify="right")
        for kind in ("micro", "macro"):
            tbl.add_row(kind, *(f"{t[kind][k]:.4f}" for k in ("precision", "recall", "f1")))
        console.print(tbl)
