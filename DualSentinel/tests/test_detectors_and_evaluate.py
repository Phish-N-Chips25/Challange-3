"""Boundary tests for the heuristic detector score and evaluate metrics."""

import numpy as np

from detectors import heuristic_score
from evaluate import evaluate_run, _confusion, _prf1, _roc_auc, _pr_auc


# ── heuristic_score ────────────────────────────────────────────────────

def test_heuristic_zero_signals():
    """Empty evidence ⇒ baseline of 0.5 (the sentinel never claims certainty)."""
    s = heuristic_score({"attck_hits": [], "smart_features": {}})
    assert 0.0 <= s <= 1.0
    assert s <= 0.55  # only the constant offset


def test_heuristic_strong_signals_saturate():
    """Many concurrent signals ⇒ score approaches 1.0."""
    wd = {
        "attck_hits": [
            {"technique": "T1059.001", "name": "PowerShell", "confidence": 0.95, "source": "rule"},
            {"technique": "T1003",     "name": "Cred Dumping", "confidence": 0.9, "source": "rule"},
            {"technique": "T1219",     "name": "RAT",          "confidence": 0.5, "source": "kb"},
            {"technique": "T1070",     "name": "Indicator Removal", "confidence": 0.45, "source": "kb"},
        ],
        "smart_features": {
            "has_lolbin": 1, "has_encoded_powershell": 1, "has_suspicious_ext": 1,
            "has_hidden_window": 1, "has_external_ip_egress": 1,
        },
        "baseline_features": {"embedding_distance": 1.6, "max_field_rare_ratio": 0.9},
    }
    s = heuristic_score(wd)
    assert s >= 0.9


def test_heuristic_score_bounded():
    rng = np.random.default_rng(0)
    for _ in range(20):
        wd = {
            "attck_hits": [
                {"technique": "T1", "name": "x", "confidence": float(rng.random()),
                 "source": "rule" if rng.random() > 0.5 else "kb"}
                for _ in range(rng.integers(0, 6))
            ],
            "smart_features": {f"f{i}": int(rng.integers(0, 2)) for i in range(8)},
            "baseline_features": {"embedding_distance": float(rng.random() * 2),
                                  "max_field_rare_ratio": float(rng.random())},
        }
        s = heuristic_score(wd)
        assert 0.0 <= s <= 1.0


# ── pure metric helpers ────────────────────────────────────────────────

def test_perfect_classifier_metrics():
    y = np.array([0, 0, 1, 1])
    pred = np.array([0, 0, 1, 1])
    cm = _confusion(y, pred)
    m = _prf1(cm)
    assert m["precision"] == 1.0 and m["recall"] == 1.0 and m["f1"] == 1.0
    assert m["accuracy"] == 1.0 and m["fpr"] == 0.0


def test_random_classifier_auc_around_half():
    rng = np.random.default_rng(42)
    y = rng.integers(0, 2, size=2000)
    scores = rng.random(2000)
    auc = _roc_auc(y, scores)
    assert 0.45 <= auc <= 0.55


def test_pr_auc_perfect():
    y = np.array([0, 0, 1, 1])
    scores = np.array([0.1, 0.2, 0.9, 0.8])
    assert _pr_auc(y, scores) == 1.0


# ── evaluate_run end-to-end (synthetic) ────────────────────────────────

def test_evaluate_run_perfect():
    windows = [
        {"window_start": "t1", "label": 0, "detector_score": 0.10},
        {"window_start": "t2", "label": 0, "detector_score": 0.20},
        {"window_start": "t3", "label": 1, "detector_score": 0.85},
        {"window_start": "t4", "label": 1, "detector_score": 0.95},
    ]
    out = evaluate_run(windows, threshold=0.6)
    assert out["detector"]["precision"] == 1.0
    assert out["detector"]["recall"] == 1.0
    assert out["detector"]["roc_auc"] == 1.0


def test_evaluate_run_skips_unlabelled():
    windows = [{"window_start": "t1", "label": -1, "detector_score": 0.9}]
    out = evaluate_run(windows, threshold=0.6)
    assert out["n_labelled"] == 0
