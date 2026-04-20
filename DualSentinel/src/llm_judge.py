"""
llm_judge.py
LLM-as-a-Judge — deep-dive validation via Ollama local.
Default model: llama3.2 (override with JUDGE_MODEL env var).

Para cada janela de risco alto:
  1. Recebe o pré-diagnóstico do SLM Analyst (phi3:mini por defeito)
  2. Recupera o evidence pack cacheado (construído uma vez por janela, partilhado com SLM)
  3. Envia ambos ao LLM Judge para validação final
  4. Devolve: técnicas ATT&CK, score [0-10], rationale, flags de evidência

Optimizações:
  - Salta o Judge para janelas com SLM pre_score<3 e needs_deep_analysis=False
  - Sort por (detector_score, SLM pre_score) para priorizar as janelas mais suspeitas
    quando os detector scores são iguais (ex.: --skip-detectors)
  - num_predict=1024 para respostas suficientemente detalhadas sem overhead excessivo
  - Sleep 0.1 s entre chamadas ao Ollama

Boas práticas anti-alucinação:
  - Judge penaliza claims sem evidência no pack
  - Pede referências explícitas a eventos do pack
  - Temperatura baixa (0.1) para respostas determinísticas
  - O pré-diagnóstico é apresentado como hipótese a validar, não como facto
"""

import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from typing import Callable, Optional, TYPE_CHECKING

import ollama
from dotenv import load_dotenv

from utils import build_evidence_pack, extract_json

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
1. A PRE-DIAGNOSIS from a first-pass SLM analyst — treat this
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
  "recommended_action": "<1-2 sentence concrete next step for the SOC analyst (e.g. 'Isolate host X and collect memory dump', 'Tune detection rule Y', 'Mark as benign \u2014 routine admin activity')>",
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
    recommended_action: str = ""
    unsupported_claims: list = field(default_factory=list)
    fp_risk: str = "low"
    detector_score: float = 0.0
    attck_rule_hits: list = field(default_factory=list)
    slm_pre_score: int = 0
    slm_summary: str = ""
    model_used: str = JUDGE_MODEL
    latency_s: float = 0.0
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return self.__dict__


# ─────────────────────────────────────────────
# LLM Judge (llama3.2 via Ollama, configurable via JUDGE_MODEL)
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

    @staticmethod
    def _extract_json(raw: str) -> dict:
        """
        Extract a JSON object from a model response that may contain prose,
        markdown fences, or other surrounding text.
        Tries in order:
          1. Direct parse
          2. Strip markdown code fences (```json ... ``` or ``` ... ```)
          3. Regex scan for first {...} block
        """
        # 1. Direct parse
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            pass

        # 2. Strip markdown fences
        fence_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", raw, re.DOTALL)
        if fence_match:
            try:
                return json.loads(fence_match.group(1))
            except json.JSONDecodeError:
                pass

        # 3. Regex scan for first {...} block — faster than manual brace counter
        brace_match = re.search(r"\{.*\}", raw, re.DOTALL)
        if brace_match:
            try:
                return json.loads(brace_match.group(0))
            except json.JSONDecodeError:
                pass

        raise json.JSONDecodeError("No valid JSON object found in response", raw, 0)

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
            _t0 = __import__("time").perf_counter()
            try:
                response = ollama.chat(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": JUDGE_SYSTEM_PROMPT},
                        {"role": "user", "content": user_content},
                    ],
                    format="json",
                    options={"temperature": 0.1, "num_predict": 1024},
                )
                try:
                    from provenance import TELEMETRY
                    TELEMETRY.record(
                        stage="judge", model=self.model,
                        duration_s=__import__("time").perf_counter() - _t0,
                        prompt_tokens=int(getattr(response, "prompt_eval_count", 0) or 0),
                        completion_tokens=int(getattr(response, "eval_count", 0) or 0),
                        ok=True,
                    )
                except Exception:
                    pass

                raw = response.message.content.strip()

                if not raw:
                    raise json.JSONDecodeError("Empty response from model", "", 0)

                parsed = extract_json(raw)
                result.anomaly_score = int(parsed.get("anomaly_score", 0))
                result.verdict = parsed.get("verdict", "normal")
                result.techniques = parsed.get("techniques", [])
                result.rationale = parsed.get("rationale", "")
                result.recommended_action = parsed.get("recommended_action", "")
                result.unsupported_claims = parsed.get("unsupported_claims", [])
                result.fp_risk = parsed.get("fp_risk", "low")
                result.latency_s = round(__import__("time").perf_counter() - _t0, 2)
                break

            except json.JSONDecodeError as e:
                logger.warning(f"JSON parse error (attempt {attempt + 1}): {e}")
                logger.debug(f"Raw response was: {raw!r}")
                if attempt == self.max_retries - 1:
                    result.error = f"JSON parse failed after {self.max_retries} attempts: {e}"
                else:
                    time.sleep(self.retry_delay)
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
        threshold: float = 0.85,
        max_windows: int = 50,
        progress_cb: Optional[Callable[[int, int, dict], None]] = None,
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

        # Mapear pré-diagnósticos por window_start para lookup O(1)
        slm_map: dict = {}
        if slm_analyses:
            for a in slm_analyses:
                slm_map[a.window_start] = a

        # Sort by detector_score desc; use SLM pre_score as tiebreaker so that
        # when all detector scores are equal (e.g. --skip-detectors) the most
        # suspicious windows (per SLM) are judged first and survive the cap.
        high_risk.sort(
            key=lambda w: (
                w.get("detector_score", 0.0),
                slm_map[w["window_start"]].pre_score
                if w.get("window_start") in slm_map else 0,
            ),
            reverse=True,
        )
        high_risk = high_risk[:max_windows]

        logger.info(
            f"LLM Judge: {len(high_risk)}/{len(windows)} janelas "
            f"(threshold={threshold}, max={max_windows})"
        )

        results = []
        skipped_low_risk = 0
        for i, w in enumerate(high_risk, 1):
            slm = slm_map.get(w.get("window_start", ""))

            # Skip Judge for windows the SLM already cleared as low-risk
            if slm and not slm.needs_deep_analysis and slm.pre_score < 3:
                skipped_low_risk += 1
                logger.debug(
                    f"Judge skipping window {i}/{len(high_risk)} "
                    f"(SLM: pre_score={slm.pre_score}, needs_deep_analysis=False)"
                )
                continue

            logger.debug(
                f"Judging window {i}/{len(high_risk)} "
                f"(detector_score={w.get('detector_score', 0.0):.3f}, "
                f"slm_pre_score={slm.pre_score if slm else 'N/A'})"
            )
            r = self.judge(w, slm_analysis=slm)
            results.append(r)
            time.sleep(0.1)
            if progress_cb is not None:
                try:
                    progress_cb(i, len(high_risk), w)
                except Exception:  # noqa: BLE001
                    pass

        if skipped_low_risk:
            logger.info(
                f"Judge complete: {len(results)} judged, "
                f"{skipped_low_risk} skipped (SLM pre_score<3, needs_deep_analysis=False)"
            )
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
        threshold: float = typer.Option(0.85),
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
