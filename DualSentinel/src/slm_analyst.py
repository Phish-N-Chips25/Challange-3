"""
slm_analyst.py
SLM Analyst — rapid first-pass triage via Ollama local.
Default model: phi3:mini (override with SLM_MODEL env var).

Para cada janela de logs de alto risco:
  1. Trivially-benign pre-filter: skips Ollama entirely when no threat signals
  2. Builds the evidence pack (cached on window dict by build_evidence_pack)
  3. Sends to SLM for structured pre-diagnosis: score, techniques, risk indicators
  4. Returns (SLMAnalysis, called_ollama) — called_ollama=False for pre-filtered windows

O pré-diagnóstico é depois passado ao LLM Judge (llama3.2 por defeito) para
validação final com grounding mais rigoroso.

Boas práticas:
  - Temperatura 0.1 para respostas determinísticas
  - num_predict=384 — suficiente para pré-diagnóstico, não análise final
  - Sleep (0.05 s) apenas após chamadas reais ao Ollama, não para janelas pré-filtradas
  - Sanitização do evidence pack (feita em build_evidence_pack)
"""

import json
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

import ollama
from dotenv import load_dotenv

from utils import build_evidence_pack, extract_json

load_dotenv()
logger = logging.getLogger(__name__)

SLM_MODEL = os.getenv("SLM_MODEL", "phi3:mini")

# ─────────────────────────────────────────────
# System prompt — conciso para caber no context
# window do modelo SLM (phi3:mini ≈ 4 k tokens)
# ─────────────────────────────────────────────

ANALYST_SYSTEM_PROMPT = """\
You are a cybersecurity log analyst performing a rapid first-pass triage \
of Sysmon/ETW log windows to flag attack indicators.

Read the EVIDENCE PACK and identify:
1. Key risk indicators directly visible in the data.
2. Potential ATT&CK techniques by name (e.g. "PowerShell Execution", \
"Credential Dumping").
3. A preliminary risk score from 0 to 10.
4. Whether the window warrants deep analysis by a senior judge.

Rules:
- Only reference what is explicitly present in the evidence pack.
- Do NOT invent process names, IPs, or file paths.
- Be brief — this is a triage, not a final verdict.

OUTPUT (valid JSON only, no markdown fences):
{
  "pre_score": <int 0-10>,
  "risk_level": "low|medium|high|critical",
  "suspected_techniques": ["<technique name>", ...],
  "risk_indicators": ["<indicator>", ...],
  "summary": "<1-2 sentence pre-diagnosis>",
  "needs_deep_analysis": <true|false>
}\
"""


# ─────────────────────────────────────────────
# SLMAnalysis dataclass
# ─────────────────────────────────────────────

@dataclass
class SLMAnalysis:
    window_start: str
    window_end: str
    pre_score: int = 0
    risk_level: str = "low"
    suspected_techniques: list = field(default_factory=list)
    risk_indicators: list = field(default_factory=list)
    summary: str = ""
    needs_deep_analysis: bool = False
    model_used: str = SLM_MODEL
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return self.__dict__

    def to_prompt_text(self) -> str:
        """Formata o pré-diagnóstico como texto para o LLM Judge."""
        tech_str = ", ".join(self.suspected_techniques) if self.suspected_techniques else "none identified"
        ind_str = "\n  - ".join(self.risk_indicators) if self.risk_indicators else "none"
        return (
            f"=== SLM PRE-DIAGNOSIS ({self.model_used}) ===\n"
            f"Pre-score: {self.pre_score}/10\n"
            f"Risk level: {self.risk_level}\n"
            f"Suspected techniques: {tech_str}\n"
            f"Risk indicators:\n  - {ind_str}\n"
            f"Summary: {self.summary}\n"
            f"Needs deep analysis: {self.needs_deep_analysis}"
        )


# ─────────────────────────────────────────────
# SLM Analyst
# ─────────────────────────────────────────────

class SLMAnalyst:
    def __init__(
        self,
        model: str = SLM_MODEL,
        max_retries: int = 3,
    ):
        self.model = model
        self.max_retries = max_retries
        self._check_connection()

    def _check_connection(self) -> None:
        try:
            ollama.list()
        except Exception as e:
            raise ConnectionError(
                f"Ollama não está disponível em localhost:11434. "
                f"Certifica-te que 'ollama serve' está a correr. Erro: {e}"
            )

    @staticmethod
    def _is_trivially_benign(window: dict) -> bool:
        """Fast pre-filter: returns True for windows with no threat signals at all.
        Skips the Ollama call entirely for clearly benign windows."""
        return (
            window.get("suspicious_process_count", 0) == 0
            and window.get("powershell_count", 0) == 0
            and not window.get("has_mimikatz", False)
            and not window.get("has_psexec", False)
            and not window.get("attck_hits")
            and window.get("network_connection_count", 0) < 5
            and window.get("lateral_movement_port_count", 0) == 0
        )

    def analyse(self, window: dict) -> tuple["SLMAnalysis", bool]:
        """Analisa uma janela e devolve (SLMAnalysis, called_ollama).
        called_ollama is False when the trivially-benign pre-filter short-circuits."""
        # Fast-path: skip Ollama entirely for windows with no threat signals
        if self._is_trivially_benign(window):
            return SLMAnalysis(
                window_start=window.get("window_start", ""),
                window_end=window.get("window_end", ""),
                pre_score=0,
                risk_level="low",
                needs_deep_analysis=False,
                summary="Trivially benign — no threat signals detected (pre-filter).",
                model_used=self.model,
            ), False

        pack = build_evidence_pack(window)

        result = SLMAnalysis(
            window_start=window.get("window_start", ""),
            window_end=window.get("window_end", ""),
            model_used=self.model,
        )

        for attempt in range(self.max_retries):
            _t0 = __import__("time").perf_counter()
            try:
                response = ollama.chat(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": ANALYST_SYSTEM_PROMPT},
                        {
                            "role": "user",
                            "content": f"Analyse this log window:\n\n{pack}",
                        },
                    ],
                    format="json",
                    options={"temperature": 0.1, "num_predict": 768},
                )
                try:
                    from provenance import TELEMETRY
                    TELEMETRY.record(
                        stage="slm", model=self.model,
                        duration_s=__import__("time").perf_counter() - _t0,
                        prompt_tokens=int(getattr(response, "prompt_eval_count", 0) or 0),
                        completion_tokens=int(getattr(response, "eval_count", 0) or 0),
                        ok=True,
                    )
                except Exception:
                    pass

                raw = response.message.content.strip()
                if not raw or len(raw) < 2:
                    raise json.JSONDecodeError("Empty response from model", "", 0)

                parsed = extract_json(raw)
                result.pre_score = int(parsed.get("pre_score", 0))
                result.risk_level = parsed.get("risk_level", "low")
                result.suspected_techniques = parsed.get("suspected_techniques", [])
                result.risk_indicators = parsed.get("risk_indicators", [])
                result.summary = parsed.get("summary", "")
                result.needs_deep_analysis = bool(parsed.get("needs_deep_analysis", False))
                break

            except json.JSONDecodeError as e:
                # Log a truncated preview of the raw output so the user can diagnose
                preview = (raw[:240].replace("\n", " ") + "…") if len(raw) > 240 else raw.replace("\n", " ")
                logger.warning(
                    "SLM JSON parse failed (attempt %d/%d): %s | raw=%r",
                    attempt + 1, self.max_retries, e, preview,
                )
                if attempt == self.max_retries - 1:
                    result.error = f"JSON parse failed: {e}"
                    # Fallback: treat as needing deep analysis so the judge still runs
                    result.needs_deep_analysis = True
                    result.summary = (
                        "SLM did not return parseable JSON for this window — "
                        "the LLM Judge made the final decision."
                    )
            except Exception as e:
                logger.error(f"SLM analyst error on attempt {attempt + 1}: {e}")
                if attempt == self.max_retries - 1:
                    result.error = str(e)
                    result.needs_deep_analysis = True
                else:
                    time.sleep(1.0)

        return result, True

    def analyse_batch(
        self,
        windows: list[dict],
        threshold: float = 0.6,
        max_calls: Optional[int] = None,
        progress_cb: Optional[Callable[[int, int, dict], None]] = None,
    ) -> list[SLMAnalysis]:
        """
        Análise em batch: filtra janelas por detector_score e analisa
        as de maior risco.

        max_calls: se fornecido, limita o número de chamadas reais ao Ollama
        (janelas trivially-benign continuam a ser pré-filtradas sem custo).
        progress_cb: callback opcional invocado como progress_cb(i, n, window)
        depois de cada janela processada — útil para feedback de UI.
        """
        high_risk = [w for w in windows if w.get("detector_score", 0.0) >= threshold]
        high_risk.sort(key=lambda w: w.get("detector_score", 0.0), reverse=True)

        cap_msg = f", max_calls={max_calls}" if max_calls is not None else ""
        logger.info(
            f"SLM analyst: {len(high_risk)}/{len(windows)} janelas "
            f"acima do threshold ({threshold}){cap_msg}"
        )

        results = []
        ollama_calls = 0
        for i, w in enumerate(high_risk, 1):
            if max_calls is not None and ollama_calls >= max_calls:
                logger.info(
                    f"SLM cap atingido ({max_calls} chamadas) — restantes "
                    f"{len(high_risk) - i + 1} janelas ignoradas."
                )
                break
            r, called_ollama = self.analyse(w)
            results.append(r)
            if called_ollama:
                ollama_calls += 1
                logger.debug(
                    f"SLM [{ollama_calls} Ollama calls / {i} processed] "
                    f"{w.get('window_start', '')[:19]} → {r.risk_level}"
                )
                time.sleep(0.05)  # Yield only after real Ollama calls
            if progress_cb is not None:
                try:
                    progress_cb(i, len(high_risk), w)
                except Exception:  # noqa: BLE001
                    pass

        pre_filtered = len(results) - ollama_calls
        logger.info(
            f"SLM complete: {ollama_calls} Ollama calls, "
            f"{pre_filtered} pre-filtered as benign, {len(results)} total"
        )
        return results


# ─────────────────────────────────────────────
# CLI standalone (debug / testes)
# ─────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    from pathlib import Path
    import typer

    app = typer.Typer()

    @app.command()
    def main(
        input: Path = typer.Option(..., help="JSON com janelas scored (output do pipeline)"),
        output: Path = typer.Option(Path("results/slm_analysis.json")),
        threshold: float = typer.Option(0.6),
        model: str = typer.Option(SLM_MODEL),
    ):
        logging.basicConfig(level=logging.INFO)
        from utils import load_json, save_json

        windows = load_json(input)
        analyst = SLMAnalyst(model=model)
        analyses = analyst.analyse_batch(windows, threshold=threshold)
        save_json([a.to_dict() for a in analyses], output)
        print(f"Saved {len(analyses)} SLM analyses → {output}")

    app()
