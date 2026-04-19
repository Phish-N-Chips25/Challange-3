"""
detectors.py
Módulo de deteção de anomalias (camada SLM):
  - IsolationForest: anomaly score por janela
  - GRUDetector: modelo de sequência para detetar desvios temporais
  - RuleTagger: tagger de técnicas ATT&CK com regras baseadas em features
"""

import json
import logging
import pickle
from pathlib import Path
from typing import Optional

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────
# ATT&CK Rule Tagger
# ─────────────────────────────────────────────

# Regras simplificadas para tagger rápido (complementa o judge)
ATTCK_RULES = [
    {
        "technique": "T1059.001",
        "name": "PowerShell",
        "condition": lambda w: w.get("powershell_count", 0) > 0,
        "confidence": 0.7,
    },
    {
        "technique": "T1021.002",
        "name": "SMB/Windows Admin Shares",
        "condition": lambda w: w.get("lateral_movement_port_count", 0) > 0
                               and w.get("network_connection_count", 0) > 2,
        "confidence": 0.6,
    },
    {
        "technique": "T1547.001",
        "name": "Registry Run Keys",
        "condition": lambda w: w.get("registry_modification_count", 0) > 3,
        "confidence": 0.5,
    },
    {
        "technique": "T1003",
        "name": "Credential Dumping",
        "condition": lambda w: w.get("has_mimikatz", False),
        "confidence": 0.95,
    },
    {
        "technique": "T1570",
        "name": "Lateral Tool Transfer (PsExec)",
        "condition": lambda w: w.get("has_psexec", False),
        "confidence": 0.85,
    },
    {
        "technique": "T1486",
        "name": "Data Encrypted for Impact (Ransomware)",
        "condition": lambda w: w.get("file_creation_count", 0) > 50
                               and w.get("suspicious_process_count", 0) > 0,
        "confidence": 0.75,
    },
    {
        "technique": "T1071",
        "name": "Application Layer Protocol (C2)",
        "condition": lambda w: w.get("outbound_unique_ips", 0) > 10,
        "confidence": 0.5,
    },
    {
        "technique": "T1055",
        "name": "Process Injection (CreateRemoteThread)",
        "condition": lambda w: w.get("remote_thread_count", 0) > 0,
        "confidence": 0.85,
    },
    {
        "technique": "T1003.001",
        "name": "LSASS Memory Access (Credential Dumping)",
        "condition": lambda w: w.get("process_access_count", 0) > 2,
        "confidence": 0.80,
    },
    {
        "technique": "T1014",
        "name": "Rootkit / Suspicious Driver Load",
        "condition": lambda w: w.get("driver_load_count", 0) > 0,
        "confidence": 0.65,
    },
    {
        "technique": "T1485",
        "name": "Data Destruction (Mass File Delete)",
        "condition": lambda w: w.get("file_delete_count", 0) > 10,
        "confidence": 0.65,
    },
    {
        "technique": "T1059.003",
        "name": "Windows Command Shell",
        "condition": lambda w: w.get("cmd_count", 0) > 3,
        "confidence": 0.55,
    },
]


def tag_techniques(window_dict: dict) -> list[dict]:
    """Aplica regras ATT&CK a uma janela e devolve técnicas detetadas."""
    hits = []
    for rule in ATTCK_RULES:
        try:
            if rule["condition"](window_dict):
                hits.append({
                    "technique": rule["technique"],
                    "name": rule["name"],
                    "confidence": rule["confidence"],
                    "source": "rule",
                })
        except Exception:
            pass
    return hits


def tag_techniques_with_kb(
    window_dict: dict,
    *,
    kb_top_k: int = 5,
    use_kb: bool = True,
) -> list[dict]:
    """Combine rule tagger with retrieval-backed ATT&CK KB hits.

    Rule hits keep their hard-coded confidence; KB hits get a confidence
    derived from their RRF score (clamped to [0.3, 0.85]) and a `source='kb'`
    marker. Rule hits take precedence when the same technique_id appears in
    both sources.

    Falls back to rule-only when the KB is unavailable.
    """
    rule_hits = tag_techniques(window_dict)
    if not use_kb:
        return rule_hits

    try:
        from attack_kb import retrieve_for_window  # lazy import (heavy deps)
    except Exception as exc:  # noqa: BLE001
        logger.debug("attack_kb import failed: %s; rule-only.", exc)
        return rule_hits

    kb_hits_raw = retrieve_for_window(window_dict, k=kb_top_k)
    if not kb_hits_raw:
        return rule_hits

    seen_ids = {h["technique"] for h in rule_hits}
    out = list(rule_hits)
    # Normalise KB scores to a confidence band so they don't dominate rules.
    if kb_hits_raw:
        max_score = max(h["score"] for h in kb_hits_raw) or 1.0
        for h in kb_hits_raw:
            tid = h.get("technique_id", "")
            if not tid or tid in seen_ids:
                continue
            confidence = 0.3 + 0.55 * (h["score"] / max_score)
            out.append({
                "technique":  tid,
                "name":       h.get("technique_name", ""),
                "confidence": round(float(confidence), 3),
                "source":     "kb",
                "evidence":   h.get("document", "")[:240],
            })
            seen_ids.add(tid)
    return out


def tag_techniques_with_kb(
    window_dict: dict,
    *,
    kb_top_k: int = 5,
    use_kb: bool = True,
) -> list[dict]:
    """Combine rule tagger with retrieval-backed ATT&CK KB hits.

    Rule hits keep their hard-coded confidence; KB hits get a confidence
    derived from their RRF score (clamped to [0.3, 0.85]) and a `source='kb'`
    marker. Rule hits take precedence when the same technique_id appears in
    both sources.

    Falls back to rule-only when the KB is unavailable.
    """
    rule_hits = tag_techniques(window_dict)
    if not use_kb:
        return rule_hits

    try:
        from attack_kb import retrieve_for_window  # lazy import (heavy deps)
    except Exception as exc:  # noqa: BLE001
        logger.debug("attack_kb import failed: %s; rule-only.", exc)
        return rule_hits

    kb_hits_raw = retrieve_for_window(window_dict, k=kb_top_k)
    if not kb_hits_raw:
        return rule_hits

    seen_ids = {h["technique"] for h in rule_hits}
    out = list(rule_hits)
    # Normalise KB scores to a confidence band so they don't dominate rules.
    if kb_hits_raw:
        max_score = max(h["score"] for h in kb_hits_raw) or 1.0
        for h in kb_hits_raw:
            tid = h.get("technique_id", "")
            if not tid or tid in seen_ids:
                continue
            confidence = 0.3 + 0.55 * (h["score"] / max_score)
            out.append({
                "technique":  tid,
                "name":       h.get("technique_name", ""),
                "confidence": round(float(confidence), 3),
                "source":     "kb",
                "evidence":   h.get("document", "")[:240],
            })
            seen_ids.add(tid)
    return out


# ─────────────────────────────────────────────
# IsolationForest Detector
# ─────────────────────────────────────────────

class IForestDetector:
    """
    Wrapper sobre sklearn IsolationForest.
    Treina em dados normais (one-class) e calcula anomaly_score por janela.
    Score normalizado: 0 = normal, 1 = anomalia extrema.
    """

    def __init__(
        self,
        n_estimators: int = 200,
        contamination: float = 0.05,
        random_state: int = 42,
    ):
        self.scaler = StandardScaler()
        self.model = IsolationForest(
            n_estimators=n_estimators,
            contamination=contamination,
            random_state=random_state,
            n_jobs=-1,
        )
        self._fitted = False

    def fit(self, X: np.ndarray) -> "IForestDetector":
        """Treina em dados normais."""
        Xs = self.scaler.fit_transform(X)
        self.model.fit(Xs)
        self._fitted = True
        logger.info(f"IForestDetector fitted on {len(X)} samples")
        return self

    def score(self, X: np.ndarray) -> np.ndarray:
        """
        Devolve anomaly score normalizado [0, 1] por amostra.
        Usa decision_function invertida + min-max normalization.
        """
        if not self._fitted:
            raise RuntimeError("Detector não foi treinado. Chama .fit() primeiro.")
        Xs = self.scaler.transform(X)
        raw = -self.model.decision_function(Xs)  # negativo: maior = mais anómalo
        # Normalizar para [0, 1]
        r_min, r_max = raw.min(), raw.max()
        if r_max > r_min:
            return (raw - r_min) / (r_max - r_min)
        return np.zeros_like(raw)

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "wb") as f:
            pickle.dump((self.scaler, self.model), f)
        logger.info(f"IForestDetector saved to {path}")

    @classmethod
    def load(cls, path: Path) -> "IForestDetector":
        det = cls()
        with open(path, "rb") as f:
            det.scaler, det.model = pickle.load(f)
        det._fitted = True
        return det


# ─────────────────────────────────────────────
# GRU Sequence Detector
# ─────────────────────────────────────────────

class GRUDetector:
    """
    GRU autoencoder para deteção de anomalias em sequências de janelas.
    Treina a reconstruir sequências normais; erro de reconstrução alto = anomalia.

    Usa PyTorch. Se torch não estiver disponível, cai para stub.
    """

    def __init__(
        self,
        feature_dim: int = 17,
        hidden_dim: int = 64,
        seq_len: int = 10,
        epochs: int = 30,
        lr: float = 1e-3,
    ):
        self.feature_dim = feature_dim
        self.hidden_dim = hidden_dim
        self.seq_len = seq_len
        self.epochs = epochs
        self.lr = lr
        self._model = None
        self._threshold: Optional[float] = None

        try:
            import torch  # noqa: F401
            self._torch_available = True
        except ImportError:
            self._torch_available = False
            logger.warning("PyTorch não disponível — GRUDetector em modo stub")

    def _build_model(self):
        import torch
        import torch.nn as nn

        class GRUAutoencoder(nn.Module):
            def __init__(self, feature_dim, hidden_dim):
                super().__init__()
                self.encoder = nn.GRU(feature_dim, hidden_dim, batch_first=True)
                self.decoder = nn.GRU(hidden_dim, feature_dim, batch_first=True)

            def forward(self, x):
                _, h = self.encoder(x)
                h_rep = h.repeat(x.size(1), 1, 1).permute(1, 0, 2)
                out, _ = self.decoder(h_rep)
                return out

        return GRUAutoencoder(self.feature_dim, self.hidden_dim)

    def fit(self, sequences: np.ndarray) -> "GRUDetector":
        """
        sequences: array de shape (N, seq_len, feature_dim)
        """
        if not self._torch_available:
            logger.warning("GRUDetector stub: .fit() ignorado")
            return self

        import torch
        import torch.nn as nn
        from torch.utils.data import DataLoader, TensorDataset

        X = torch.tensor(sequences, dtype=torch.float32)
        dataset = TensorDataset(X)
        loader = DataLoader(dataset, batch_size=32, shuffle=True)

        self._model = self._build_model()
        optimizer = torch.optim.Adam(self._model.parameters(), lr=self.lr)
        criterion = nn.MSELoss()

        self._model.train()
        for epoch in range(self.epochs):
            total_loss = 0.0
            for (batch,) in loader:
                optimizer.zero_grad()
                recon = self._model(batch)
                loss = criterion(recon, batch)
                loss.backward()
                optimizer.step()
                total_loss += loss.item()
            if (epoch + 1) % 10 == 0:
                logger.info(f"GRU epoch {epoch+1}/{self.epochs} loss={total_loss/len(loader):.4f}")

        # Calcular threshold como percentil 95 do erro de reconstrução em treino
        errors = self._reconstruction_errors(sequences)
        self._threshold = float(np.percentile(errors, 95))
        logger.info(f"GRUDetector fitted. Threshold (p95)={self._threshold:.4f}")
        return self

    def _reconstruction_errors(self, sequences: np.ndarray) -> np.ndarray:
        if not self._torch_available or self._model is None:
            return np.zeros(len(sequences))
        import torch
        self._model.eval()
        with torch.no_grad():
            X = torch.tensor(sequences, dtype=torch.float32)
            recon = self._model(X).numpy()
        return np.mean((sequences - recon) ** 2, axis=(1, 2))

    def score(self, sequences: np.ndarray) -> np.ndarray:
        """Devolve erro de reconstrução por sequência."""
        return self._reconstruction_errors(sequences)

    def save(self, path: Path) -> None:
        if self._model is None:
            return
        import torch
        path.parent.mkdir(parents=True, exist_ok=True)
        torch.save({
            "state_dict": self._model.state_dict(),
            "config": {
                "feature_dim": self.feature_dim,
                "hidden_dim": self.hidden_dim,
                "seq_len": self.seq_len,
            },
            "threshold": self._threshold,
        }, path)
        logger.info(f"GRUDetector saved to {path}")

    @classmethod
    def load(cls, path: Path) -> "GRUDetector":
        import torch
        ckpt = torch.load(path, map_location="cpu")
        cfg = ckpt["config"]
        det = cls(**cfg)
        det._model = det._build_model()
        det._model.load_state_dict(ckpt["state_dict"])
        det._threshold = ckpt.get("threshold")
        det._torch_available = True
        return det


# ─────────────────────────────────────────────
# Ensemble scorer
# ─────────────────────────────────────────────

def ensemble_score(
    iforest_score: float,
    gru_score: float,
    has_attck_hits: bool,
    weights: tuple = (0.5, 0.3, 0.2),
) -> float:
    """
    Combina os três sinais num score final [0, 1].
    weights = (iforest_w, gru_w, rule_w)

    DEPRECATED — kept only for backwards compatibility with notebooks/tests.
    The pipeline now uses :func:`heuristic_score`, which fuses ATT&CK rule
    hits, KB candidates, smart features and baseline deviation without
    requiring IForest / GRU.
    """
    rule_score = 1.0 if has_attck_hits else 0.0
    total = weights[0] * iforest_score + weights[1] * gru_score + weights[2] * rule_score
    return float(np.clip(total, 0.0, 1.0))


def heuristic_score(window: dict) -> float:
    """Fuses the four detector signals — ATT&CK rule hits, KB retrieval
    candidates, smart-feature indicators and baseline deviation — into a
    single anomaly score in [0, 1].

    Design choices:
        - A confirmed rule hit alone anchors the score at ≥ 0.5 (it is a
          deterministic, audited signal).
        - KB candidates are weaker (retrieval ≠ confirmation) — capped at
          +0.15.
        - Smart-feature flags (obfuscation, LOLBINs, suspicious paths,
          lateral ports, suspicious parent→child pairs) each add +0.08.
        - Baseline deviation (centroid distance + rare token ratio) adds
          up to +0.25 — surfaces novel windows that no rule fires on.
    """
    score = 0.0

    hits = window.get("attck_hits", []) or []
    rule_hits = [h for h in hits if h.get("source", "rule") == "rule"]
    kb_hits   = [h for h in hits if h.get("source") == "kb"]
    if rule_hits:
        max_conf = max(float(h.get("confidence", 0.5)) for h in rule_hits)
        score += 0.5 + 0.4 * max_conf + 0.05 * (len(rule_hits) - 1)
    score += min(0.15, 0.05 * len(kb_hits))

    smart = window.get("smart_features", {}) or {}
    smart_signals = [
        smart.get("cmdline_obfuscation_hits", 0) > 0,
        smart.get("cmdline_lolbin_calls", 0) > 0,
        smart.get("cmdline_b64_blob_count", 0) > 0,
        smart.get("reg_suspicious_path_hits", 0) > 0,
        smart.get("path_executable_writes", 0) > 0 and (
            smart.get("path_temp_ratio", 0) > 0
            or smart.get("path_appdata_ratio", 0) > 0
        ),
        float(smart.get("port_lateral_ratio", 0)) >= 0.3,
        smart.get("proctree_suspicious_pairs", 0) > 0,
    ]
    score += 0.08 * sum(smart_signals)

    baseline = window.get("baseline_features", {}) or {}
    rare_max = max(
        (float(baseline.get(k, 0.0)) for k in (
            "cmdline_rare_token_ratio", "registry_rare_token_ratio",
            "process_rare_token_ratio", "path_rare_token_ratio",
        )),
        default=0.0,
    )
    # emb distance is unbounded; ~1.5 is "very far" for L2-normalised hash buckets
    emb_dev = min(1.0, float(baseline.get("emb_distance_to_baseline", 0.0)) / 1.5)
    score += 0.15 * emb_dev + 0.10 * rare_max

    return float(np.clip(score, 0.0, 1.0))
