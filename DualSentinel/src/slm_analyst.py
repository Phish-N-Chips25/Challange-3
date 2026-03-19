"""
slm_analyst.py
SLM Analyst usando Phi-3 Medium via Ollama local.

Para cada janela de logs de alto risco:
  1. Constrói o evidence pack
  2. Envia para Phi-3 Medium (modelo local, rápido)
  3. Emite um pré-diagnóstico estruturado: score preliminar, técnicas
     suspeitas e indicadores de risco

O pré-diagnóstico é depois passado ao LLM Judge (Llama 3.1) para
validação final com grounding mais rigoroso.

Boas práticas:
  - Temperatura 0.1 para respostas determinísticas
  - Número de tokens limitado (512) — só pré-diagnóstico, não análise final
  - Sanitização do evidence pack (feita em build_evidence_pack)
"""

import json
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Optional

import ollama
from dotenv import load_dotenv

from utils import build_evidence_pack

load_dotenv()
logger = logging.getLogger(__name__)

SLM_MODEL = os.getenv("SLM_MODEL", "phi3:mini")

# ─────────────────────────────────────────────
# System prompt — deve ser conciso para caber
# no context window do Phi-3 Medium (4 k–128 k)
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
            f"=== SLM PRE-DIAGNOSIS (Phi-3 Medium) ===\n"
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
        max_retries: int = 2,
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

    def analyse(self, window: dict) -> SLMAnalysis:
        """Analisa uma janela e devolve SLMAnalysis."""
        pack = build_evidence_pack(window)

        result = SLMAnalysis(
            window_start=window.get("window_start", ""),
            window_end=window.get("window_end", ""),
            model_used=self.model,
        )

        for attempt in range(self.max_retries):
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
                    options={"temperature": 0.1, "num_predict": 1024},
                )

                raw = response.message.content.strip()
                if not raw:
                    raise json.JSONDecodeError("Empty response from model", "", 0)

                parsed = json.loads(raw)
                result.pre_score = int(parsed.get("pre_score", 0))
                result.risk_level = parsed.get("risk_level", "low")
                result.suspected_techniques = parsed.get("suspected_techniques", [])
                result.risk_indicators = parsed.get("risk_indicators", [])
                result.summary = parsed.get("summary", "")
                result.needs_deep_analysis = bool(parsed.get("needs_deep_analysis", False))
                break

            except json.JSONDecodeError as e:
                logger.warning(f"JSON parse error on attempt {attempt + 1}: {e}")
                logger.debug(f"Raw SLM response was: {raw!r}")
                if attempt == self.max_retries - 1:
                    result.error = f"JSON parse failed: {e}"
                    # Fallback: treat as needing deep analysis so the judge still runs
                    result.needs_deep_analysis = True
                    result.summary = f"SLM parse error — escalating to judge: {e}"
            except Exception as e:
                logger.error(f"SLM analyst error on attempt {attempt + 1}: {e}")
                if attempt == self.max_retries - 1:
                    result.error = str(e)
                    result.needs_deep_analysis = True
                else:
                    time.sleep(1.0)

        return result

    def analyse_batch(
        self,
        windows: list[dict],
        threshold: float = 0.6,
    ) -> list[SLMAnalysis]:
        """
        Análise em batch: filtra janelas por detector_score e analisa
        as de maior risco.
        """
        high_risk = [w for w in windows if w.get("detector_score", 0.0) >= threshold]
        high_risk.sort(key=lambda w: w.get("detector_score", 0.0), reverse=True)

        logger.info(
            f"SLM analyst: {len(high_risk)}/{len(windows)} janelas "
            f"acima do threshold ({threshold})"
        )

        results = []
        for i, w in enumerate(high_risk, 1):
            logger.info(
                f"SLM analysing window {i}/{len(high_risk)} "
                f"(detector_score={w.get('detector_score', 0.0):.3f})"
            )
            r = self.analyse(w)
            results.append(r)
            time.sleep(0.2)  # Dar folga ao Ollama entre chamadas

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
