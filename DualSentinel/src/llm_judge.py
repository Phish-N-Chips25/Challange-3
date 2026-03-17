"""
llm_judge.py
LLM-as-a-Judge usando Llama 3.1 via Ollama local.

Para cada janela de risco alto:
  1. Recebe o pré-diagnóstico do SLM Analyst (Phi-3 Medium)
  2. Constrói o evidence pack completo
  3. Envia ambos ao Llama 3.1 para validação final
  4. Devolve: técnicas ATT&CK, score [0-10], rationale, flags de evidência

Boas práticas anti-alucinação:
  - Judge penaliza claims sem evidência no pack
  - Pede referências explícitas a eventos do pack
  - Temperatura baixa (0.1) para respostas determinísticas
  - O pré-diagnóstico é apresentado como hipótese a validar, não como facto
"""

import json
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Optional, TYPE_CHECKING

import ollama
from dotenv import load_dotenv

from utils import build_evidence_pack

if TYPE_CHECKING:
    from slm_analyst import SLMAnalysis

load_dotenv()
logger = logging.getLogger(__name__)

JUDGE_MODEL = os.getenv("JUDGE_MODEL", "llama3.2")

# ─────────────────────────────────────────────
# Rubrica do judge
# ─────────────────────────────────────────────

JUDGE_SYSTEM_PROMPT = """\
You are a senior cybersecurity analyst and LLM judge evaluating Sysmon/ETW \
log windows for signs of attack.

You will receive:
1. A PRE-DIAGNOSIS from a first-pass SLM analyst (Phi-3 Medium) — treat this
   as a hypothesis to validate, not as established fact.
2. The full EVIDENCE PACK with raw log statistics and event samples.

Your task:
1. Validate or refute the SLM pre-diagnosis using evidence from the pack.
2. Map observed behaviors to ATT&CK techniques. Only reference techniques you
   can directly support with evidence from the pack.
3. Assign an overall anomaly score (0-10, integer).
4. Write a concise rationale (2-3 sentences).
5. Flag any SLM claims NOT supported by the evidence pack.

SCORING RUBRIC:
  0-2 : Normal / benign activity
  3-4 : Mildly suspicious (elevated entropy, unusual process counts)
  5-6 : Moderately suspicious (suspicious processes, lateral movement indicators)
  7-8 : Highly suspicious (confirmed C2 indicators, mimikatz, psexec, ransomware)
  9-10: Critical (confirmed APT TTPs with multiple corroborated evidence points)

STRICT RULES:
- NEVER claim a technique unless you cite a specific event or stat from the pack.
- If a rule tagger hit has no corroborating events, mark its confidence "low".
- Do NOT hallucinate process names, IPs, or file paths not present in the pack.
- Use "Evidence: [cite]" for each technique you list.

OUTPUT (valid JSON only, no markdown fences):
{
  "anomaly_score": <int 0-10>,
  "verdict": "normal|suspicious|malicious",
  "techniques": [
    {
      "technique_id": "T1059.001",
      "name": "PowerShell",
      "confidence": "high|medium|low",
      "evidence": "powershell_count=5 in stats; event [03] EID=1 proc=powershell.exe"
    }
  ],
  "rationale": "<2-3 sentence summary>",
  "unsupported_claims": [],
  "fp_risk": "high|medium|low"
}\
"""


# ─────────────────────────────────────────────
# Judge result dataclass
# ─────────────────────────────────────────────

@dataclass
class JudgeResult:
    window_start: str
    window_end: str
    anomaly_score: int = 0
    verdict: str = "normal"
    techniques: list = field(default_factory=list)
    rationale: str = ""
    unsupported_claims: list = field(default_factory=list)
    fp_risk: str = "low"
    detector_score: float = 0.0
    attck_rule_hits: list = field(default_factory=list)
    slm_pre_score: int = 0
    slm_summary: str = ""
    model_used: str = JUDGE_MODEL
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return self.__dict__


# ─────────────────────────────────────────────
# LLM Judge (Llama 3.1 via Ollama)
# ─────────────────────────────────────────────

class LLMJudge:
    def __init__(
        self,
        model: str = JUDGE_MODEL,
        max_retries: int = 3,
        retry_delay: float = 2.0,
    ):
        self.model = model
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self._check_connection()

    def _check_connection(self) -> None:
        try:
            ollama.list()
        except Exception as e:
            raise ConnectionError(
                f"Ollama não está disponível em localhost:11434. "
                f"Certifica-te que 'ollama serve' está a correr. Erro: {e}"
            )

    def judge(self, window: dict, slm_analysis: Optional["SLMAnalysis"] = None) -> JudgeResult:
        """
        Avalia uma janela e devolve JudgeResult.

        slm_analysis: pré-diagnóstico do SLM Analyst (opcional).
          Quando fornecido, é incluído no prompt como hipótese a validar.
        """
        pack = build_evidence_pack(window)

        result = JudgeResult(
            window_start=window.get("window_start", ""),
            window_end=window.get("window_end", ""),
            detector_score=window.get("detector_score", 0.0),
            attck_rule_hits=window.get("attck_hits", []),
            model_used=self.model,
        )

        if slm_analysis is not None:
            result.slm_pre_score = slm_analysis.pre_score
            result.slm_summary = slm_analysis.summary

        # Constrói o user message: pré-diagnóstico (se disponível) + evidence pack
        if slm_analysis is not None:
            user_content = (
                f"{slm_analysis.to_prompt_text()}\n\n"
                f"Validate the pre-diagnosis above using the evidence pack below:\n\n"
                f"{pack}"
            )
        else:
            user_content = f"Evaluate this log window:\n\n{pack}"

        for attempt in range(self.max_retries):
            try:
                response = ollama.chat(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": JUDGE_SYSTEM_PROMPT},
                        {"role": "user", "content": user_content},
                    ],
                    options={"temperature": 0.1, "num_predict": 1024},
                )

                raw = response.message.content.strip()
                # Limpar possíveis markdown fences
                if raw.startswith("```"):
                    raw = raw.split("```")[1]
                    if raw.startswith("json"):
                        raw = raw[4:]

                parsed = json.loads(raw)
                result.anomaly_score = int(parsed.get("anomaly_score", 0))
                result.verdict = parsed.get("verdict", "normal")
                result.techniques = parsed.get("techniques", [])
                result.rationale = parsed.get("rationale", "")
                result.unsupported_claims = parsed.get("unsupported_claims", [])
                result.fp_risk = parsed.get("fp_risk", "low")
                break

            except json.JSONDecodeError as e:
                logger.warning(f"JSON parse error (attempt {attempt + 1}): {e}")
                if attempt == self.max_retries - 1:
                    result.error = f"JSON parse failed: {e}"
            except Exception as e:
                logger.error(f"Judge error (attempt {attempt + 1}): {e}")
                if attempt == self.max_retries - 1:
                    result.error = str(e)
                else:
                    time.sleep(self.retry_delay)

        return result

    def judge_batch(
        self,
        windows: list[dict],
        slm_analyses: Optional[list] = None,
        threshold: float = 0.6,
        max_windows: int = 50,
    ) -> list[JudgeResult]:
        """
        Filtra janelas pelo detector_score e avalia as de maior risco.

        slm_analyses: lista de SLMAnalysis na mesma ordem de `windows`
          (indexadas por window_start). Quando fornecida, o pré-diagnóstico
          é incluído no prompt do judge.
        """
        high_risk = [
            w for w in windows if w.get("detector_score", 0.0) >= threshold
        ]
        high_risk.sort(key=lambda w: w.get("detector_score", 0.0), reverse=True)
        high_risk = high_risk[:max_windows]

        # Mapear pré-diagnósticos por window_start para lookup O(1)
        slm_map: dict = {}
        if slm_analyses:
            for a in slm_analyses:
                slm_map[a.window_start] = a

        logger.info(
            f"LLM Judge: {len(high_risk)}/{len(windows)} janelas "
            f"(threshold={threshold}, max={max_windows})"
        )

        results = []
        for i, w in enumerate(high_risk, 1):
            slm = slm_map.get(w.get("window_start", ""))
            logger.info(
                f"Judging window {i}/{len(high_risk)} "
                f"(detector_score={w.get('detector_score', 0.0):.3f}, "
                f"slm_pre_score={slm.pre_score if slm else 'N/A'})"
            )
            r = self.judge(w, slm_analysis=slm)
            results.append(r)
            time.sleep(0.5)

        return results


# ─────────────────────────────────────────────
# CLI standalone (debug / testes)
# ─────────────────────────────────────────────

if __name__ == "__main__":
    from pathlib import Path
    import typer

    app = typer.Typer()

    @app.command()
    def main(
        input: Path = typer.Option(..., help="JSON com janelas scored (output do pipeline)"),
        output: Path = typer.Option(Path("results/judge_results.json")),
        threshold: float = typer.Option(0.6),
        max_windows: int = typer.Option(50),
        model: str = typer.Option(JUDGE_MODEL),
    ):
        logging.basicConfig(level=logging.INFO)
        from utils import load_json, save_json

        windows = load_json(input)
        judge = LLMJudge(model=model)
        results = judge.judge_batch(windows, threshold=threshold, max_windows=max_windows)
        save_json([r.to_dict() for r in results], output)
        logger.info(f"Saved {len(results)} judge results → {output}")

    app()
