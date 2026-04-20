"""
pipeline.py
Orquestrador principal do Challenge 3 MEIA.

Fluxo:
  1. Parse + windowing (preprocessor)
  2. Feature extraction + baseline self-supervised
  3. ATT&CK rule tagging + KB retrieval híbrido
  4. Heuristic scoring (rules + smart features + baseline deviation)
  5. SLM Analyst (Phi-3) + LLM Judge (Llama 3.1) nas janelas de alto risco
  6. Geração de relatório Markdown
"""

import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional

import numpy as np
import pandas as pd
import typer
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table

# load_dotenv MUST run before local imports so module-level os.getenv() calls
# in slm_analyst.py and llm_judge.py pick up .env values.
load_dotenv()

from preprocessor import make_windows, parse_csv, parse_evtx, WindowFeatures
from detectors import tag_techniques_with_kb, heuristic_score
from chains import make_chains, chains_for_window
from llm_judge import LLMJudge, JudgeResult
from slm_analyst import SLMAnalyst
from provenance import set_global_seed, write_run_manifest, TELEMETRY
console = Console()
logger = logging.getLogger(__name__)

ANOMALY_THRESHOLD = float(os.getenv("ANOMALY_THRESHOLD", 0.85))
WINDOW_SIZE = int(os.getenv("WINDOW_SIZE_SECONDS", 60))
MAX_EVENTS = int(os.getenv("MAX_EVENTS_PER_WINDOW", 200))


# ─────────────────────────────────────────────
# Report generator
# ─────────────────────────────────────────────

def generate_report(
    windows: list[dict],
    judge_results: list[JudgeResult],
    output_dir: Path,
    dataset: str,
) -> Path:
    """Gera relatório Markdown com resumo da avaliação."""
    ts = datetime.now().strftime("%Y-%m-%d_%H-%M")
    report_path = output_dir / f"report_{dataset}_{ts}.md"

    malicious = [r for r in judge_results if r.verdict == "malicious"]
    suspicious = [r for r in judge_results if r.verdict == "suspicious"]
    normal = [r for r in judge_results if r.verdict == "normal"]

    # Técnicas mais frequentes
    technique_counts: dict = {}
    for r in judge_results:
        for t in r.techniques:
            tid = t.get("technique_id", "unknown")
            technique_counts[tid] = technique_counts.get(tid, 0) + 1

    lines = [
        f"# MEIA Challenge 3 — Anomaly Detection Report",
        f"",
        f"**Dataset:** {dataset}  ",
        f"**Generated:** {datetime.now().isoformat()}  ",
        f"**Total windows analysed:** {len(windows)}  ",
        f"**Windows sent to judge:** {len(judge_results)}  ",
        f"",
        f"## Summary",
        f"",
        f"| Verdict | Count |",
        f"|---|---|",
        f"| Malicious | {len(malicious)} |",
        f"| Suspicious | {len(suspicious)} |",
        f"| Normal | {len(normal)} |",
        f"",
        f"## Top ATT&CK Techniques",
        f"",
        f"| Technique | Count |",
        f"|---|---|",
    ]

    for tid, count in sorted(technique_counts.items(), key=lambda x: -x[1])[:10]:
        lines.append(f"| {tid} | {count} |")

    lines += ["", "## High-Risk Windows", ""]

    high_risk = [r for r in judge_results if r.anomaly_score >= 7]
    if not high_risk:
        lines.append("_No windows scored ≥ 7._")
    else:
        for r in sorted(high_risk, key=lambda x: -x.anomaly_score):
            lines += [
                f"### Window {r.window_start} → {r.window_end}",
                f"",
                f"**Score:** {r.anomaly_score}/10  ",
                f"**Verdict:** {r.verdict}  ",
                f"**Detector score:** {r.detector_score:.3f}  ",
                f"**FP risk:** {r.fp_risk}  ",
                f"",
                f"**Rationale:** {r.rationale}",
                f"",
                f"**Techniques:**",
            ]
            for t in r.techniques:
                lines.append(
                    f"- `{t.get('technique_id')}` {t.get('name')} "
                    f"(confidence: {t.get('confidence')}) — {t.get('evidence', '')}"
                )
            if r.unsupported_claims:
                lines.append(f"\n**Unsupported claims flagged:** {r.unsupported_claims}")
            lines.append("")

    lines += [
        "## All Judge Results",
        "",
        "| Window start | Score | Verdict | Detector score | FP risk |",
        "|---|---|---|---|---|",
    ]
    for r in sorted(judge_results, key=lambda x: -x.anomaly_score):
        lines.append(
            f"| {r.window_start[:19]} | {r.anomaly_score}/10 | {r.verdict} "
            f"| {r.detector_score:.3f} | {r.fp_risk} |"
        )

    report_path.write_text("\n".join(lines), encoding="utf-8")
    return report_path


# ─────────────────────────────────────────────
# Main pipeline
# ─────────────────────────────────────────────

def run_pipeline(
    input_path: Path,
    dataset: str = "lmd",
    output_dir: Optional[Path] = None,
    model_dir: Optional[Path] = None,
    skip_judge: bool = False,
    threshold: Optional[float] = None,
    evaluate: bool = False,
    max_rows: Optional[int] = None,
    use_kb: bool = True,
    max_llm_calls: Optional[int] = None,
    seed: int = 42,
    progress_cb: Optional[Callable[[dict], None]] = None,
    slm_model: Optional[str] = None,
    judge_model: Optional[str] = None,
) -> dict:
    """
    Pipeline completo. Devolve dict com resultados e caminhos de output.

    threshold: sobrepõe ANOMALY_THRESHOLD do .env quando fornecido.
    progress_cb: callback opcional que recebe dicts com chaves
      {stage, message, progress (0-1), detail?} — usado pelo frontend para
      mostrar feedback detalhado durante execução em background thread.
    """
    def _emit(stage: str, message: str, progress: float, **extra) -> None:
        if progress_cb is None:
            return
        try:
            progress_cb({
                "stage":    stage,
                "message":  message,
                "progress": max(0.0, min(1.0, float(progress))),
                **extra,
            })
        except Exception:  # noqa: BLE001  — never let UI callbacks break the pipeline
            pass

    set_global_seed(seed)
    effective_threshold = threshold if threshold is not None else ANOMALY_THRESHOLD
    ts = datetime.now().strftime("%Y-%m-%d_%H-%M")
    if output_dir is None:
        output_dir = Path("results") / ts
    output_dir.mkdir(parents=True, exist_ok=True)

    # ── 1. Parse ──────────────────────────────
    console.print(f"[bold]Step 1:[/bold] Parsing {input_path.name}...")
    if input_path.suffix.lower() == ".evtx":
        df = parse_evtx(input_path)
        if max_rows:
            df = df.head(max_rows)
    else:
        df = parse_csv(input_path, dataset=dataset, nrows=max_rows)
    if max_rows:
        console.print(f"  → Limitado a {max_rows} linhas")

    if df.empty:
        console.print("[red]Erro: nenhum evento carregado.")
        return {}

    # ── 2. Windowing + chains ─────────────────
    _emit("windowing", f"Janelamento {WINDOW_SIZE}s + extração de cadeias de processos…", 0.15)
    console.print(f"[bold]Step 2:[/bold] Windowing ({WINDOW_SIZE}s) + chain extraction...")
    windows: list[WindowFeatures] = list(
        make_windows(df, window_size_seconds=WINDOW_SIZE, max_events=MAX_EVENTS)
    )
    chains = make_chains(df, min_length=2)
    console.print(f"  → {len(windows)} janelas, {len(chains)} process chains")

    # Self-supervised benign baseline (centroid + per-field token rarity).
    # Bulk-of-windows assumption (most windows are benign); the resulting
    # signals feed both the heuristic scorer and the LLM evidence pack.
    from embeddings import BenignBaseline
    baseline = BenignBaseline().fit(windows)
    baseline.annotate(windows)

    # ── 3. ATT&CK rule tagging + KB retrieval + heuristic score ──
    kb_label = "+ KB retrieval" if use_kb else ""
    _emit("detect", f"Regras ATT&CK {kb_label} + scoring heurístico ({len(windows)} janelas)…", 0.28)
    console.print(f"[bold]Step 3:[/bold] ATT&CK rule tagging {kb_label} + heuristic scoring...")
    window_dicts = []
    for i, w in enumerate(windows):
        wd = w.to_dict()
        wd["attck_hits"] = tag_techniques_with_kb(wd, use_kb=use_kb)
        # Attach the longest overlapping chain as 'peak_chain' for the evidence pack.
        try:
            ws_dt = pd.to_datetime(wd.get("window_start"))
            we_dt = pd.to_datetime(wd.get("window_end"))
            overlap = chains_for_window(chains, ws_dt, we_dt)
            if overlap:
                peak = max(overlap, key=lambda c: (c.length, c.child_count))
                wd["peak_chain"] = peak.to_dict()
        except Exception as exc:  # noqa: BLE001
            logger.debug("peak_chain attach failed for window %d: %s", i, exc)
        wd["detector_score"] = heuristic_score(wd)
        window_dicts.append(wd)

    # Guardar janelas enriquecidas + chains
    windows_path = output_dir / "windows_scored.json"
    with open(windows_path, "w") as f:
        json.dump(window_dicts, f, indent=2, default=str)
    chains_path = output_dir / "chains.json"
    with open(chains_path, "w") as f:
        json.dump([c.to_dict() for c in chains], f, indent=2, default=str)

    high_risk_count = sum(1 for w in window_dicts if w["detector_score"] >= effective_threshold)
    _emit("detect", f"{high_risk_count}/{len(window_dicts)} janelas acima do threshold {effective_threshold}", 0.42,
          flagged=high_risk_count, total_windows=len(window_dicts))
    console.print(f"  → {high_risk_count}/{len(window_dicts)} janelas acima do threshold ({effective_threshold})")

    # Persist rendered evidence packs for high-risk windows (debug aid).
    from utils import build_evidence_pack
    ep_path = output_dir / "evidence_packs.json"
    ep_payload = []
    for wd in window_dicts:
        if wd["detector_score"] >= effective_threshold:
            ep_payload.append({
                "window_start":   wd.get("window_start"),
                "window_end":     wd.get("window_end"),
                "detector_score": wd["detector_score"],
                "evidence_pack":  build_evidence_pack(wd),
            })
    with open(ep_path, "w", encoding="utf-8") as f:
        json.dump(ep_payload, f, indent=2, default=str, ensure_ascii=False)

    # ── 4. SLM Analyst (Phi-3) + LLM Judge (Llama 3.1) ──
    judge_results: list[JudgeResult] = []
    if not skip_judge:
        # ── 4a. SLM pre-diagnosis (Phi-3 Medium) ──
        slm_analyses = []
        try:
            effective_slm = slm_model or os.getenv('SLM_MODEL', 'phi3:mini')
            _emit("slm", f"SLM ({effective_slm}) — pré-diagnóstico de {high_risk_count} janelas…", 0.50,
                  model=effective_slm, targets=high_risk_count)
            console.print(
                f"[bold]Step 4a:[/bold] SLM pre-diagnosis "
                f"({effective_slm})..."
            )
            analyst = SLMAnalyst(model=effective_slm)

            def _slm_progress(i: int, n: int, win: dict) -> None:
                frac = 0.50 + 0.15 * (i / max(1, n))
                _emit("slm", f"SLM: janela {i}/{n}", frac, sub_i=i, sub_n=n)

            slm_analyses = analyst.analyse_batch(
                window_dicts,
                threshold=effective_threshold,
                max_calls=max_llm_calls,
                progress_cb=_slm_progress,
            )
            console.print(f"  → {len(slm_analyses)} janelas pré-diagnosticadas pelo SLM")

            slm_path = output_dir / "slm_analyses.json"
            with open(slm_path, "w") as f:
                json.dump([a.to_dict() for a in slm_analyses], f, indent=2, default=str)
        except Exception as e:
            console.print(f"[yellow]SLM analyst skipped: {e}[/yellow]")

        # ── 4b. LLM Judge final validation (Llama 3.1) ──
        try:
            effective_judge = judge_model or os.getenv('JUDGE_MODEL', 'llama3.2')
            _emit("judge", f"Judge ({effective_judge}) — validação final…", 0.66, model=effective_judge)
            console.print(
                f"[bold]Step 4b:[/bold] LLM judge validation "
                f"({effective_judge})..."
            )
            judge = LLMJudge(model=effective_judge)

            def _judge_progress(i: int, n: int, win: dict) -> None:
                frac = 0.66 + 0.24 * (i / max(1, n))
                _emit("judge", f"Judge: janela {i}/{n}", frac, sub_i=i, sub_n=n)

            judge_results = judge.judge_batch(
                window_dicts,
                slm_analyses=slm_analyses if slm_analyses else None,
                threshold=effective_threshold,
                max_windows=max_llm_calls if max_llm_calls is not None else 50,
                progress_cb=_judge_progress,
            )

            judge_path = output_dir / "judge_results.json"
            with open(judge_path, "w") as f:
                json.dump([r.to_dict() for r in judge_results], f, indent=2, default=str)
            console.print(f"  → {len(judge_results)} janelas validadas pelo judge")
        except Exception as e:
            console.print(f"[yellow]LLM judge skipped: {e}[/yellow]")
    else:
        console.print("[dim]Step 4: SLM + LLM judge skipped (--skip-judge)[/dim]")

    # ── 5. Relatório ──────────────────────────
    _emit("report", "A gerar relatório Markdown…", 0.92)
    console.print("[bold]Step 5:[/bold] Generating report...")
    report_path = generate_report(window_dicts, judge_results, output_dir, dataset)

    # ── 6. Métricas (se --evaluate) ───────────
    if evaluate and "label" in df.columns:
        _emit("metrics", "A calcular métricas (Precision, Recall, F1, AUC)…", 0.97)
        console.print("[bold]Step 6:[/bold] Computing metrics...")
        from evaluate import evaluate_run
        evaluate_run(
            windows=window_dicts,
            judge_results=[r.to_dict() for r in judge_results] if judge_results else None,
            threshold=effective_threshold,
            output_path=output_dir / "metrics.json",
        )

    # ── Provenance: telemetry + manifest ──────────────────────────────
    try:
        TELEMETRY.dump(output_dir / "telemetry.json")
    except Exception as exc:  # noqa: BLE001
        logger.debug("telemetry dump failed: %s", exc)
    try:
        write_run_manifest(
            output_dir,
            input_path=input_path,
            dataset=dataset,
            threshold=effective_threshold,
            seed=seed,
            window_size_s=WINDOW_SIZE,
            max_events=MAX_EVENTS,
            use_kb=use_kb,
            skip_judge=skip_judge,
            max_llm_calls=max_llm_calls,
            n_windows=len(window_dicts),
            n_high_risk=int(high_risk_count),
            n_judged=len(judge_results),
            slm_model=os.getenv("SLM_MODEL", ""),
            judge_model=os.getenv("JUDGE_MODEL", ""),
        )
    except Exception as exc:  # noqa: BLE001
        logger.debug("manifest write failed: %s", exc)

    # Sumário final
    console.print("")
    table = Table(title="Pipeline complete", show_header=True)
    table.add_column("Output", style="cyan")
    table.add_column("Path")
    table.add_row("Windows scored", str(windows_path))
    table.add_row("Chains", str(chains_path))
    table.add_row("Evidence packs", str(ep_path))
    if judge_results:
        table.add_row("SLM analyses", str(output_dir / "slm_analyses.json"))
        table.add_row("Judge results", str(output_dir / "judge_results.json"))
    table.add_row("Report", str(report_path))
    console.print(table)

    return {
        "windows": window_dicts,
        "judge_results": [r.to_dict() for r in judge_results],
        "output_dir": str(output_dir),
        "report": str(report_path),
    }


def _print_metrics(window_dicts: list, df) -> None:
    """Deprecated stub — real metrics live in evaluate.evaluate_run()."""
    from evaluate import evaluate_run
    evaluate_run(window_dicts, threshold=ANOMALY_THRESHOLD)


# ─────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────

app = typer.Typer()

@app.command()
def main(
    input: Path = typer.Option(..., help="CSV ou EVTX de input"),
    dataset: str = typer.Option("lmd", help="Formato: lmd, splunk, silrad"),
    output_dir: Optional[Path] = typer.Option(None, help="Directório de output"),
    model_dir: Optional[Path] = typer.Option(None, help="Directório com modelos pré-treinados"),
    skip_judge: bool = typer.Option(False, help="Salta o LLM judge (economiza tokens)"),
    threshold: Optional[float] = typer.Option(None, help="Sobrepõe ANOMALY_THRESHOLD do .env (default 0.85)"),
    evaluate: bool = typer.Option(False, help="Calcula métricas (requer labels)"),
    use_kb: bool = typer.Option(True, "--use-kb/--no-use-kb", help="Augmenta o tagger com retrieval do ATT&CK KB (Chroma)"),
    max_llm_calls: Optional[int] = typer.Option(None, "--max-llm-calls", help="Limita chamadas ao Ollama em cada estágio LLM (SLM e Judge). \u00datil para smoke tests."),
    seed: int = typer.Option(42, "--seed", help="Seed global para reprodutibilidade (numpy + random + PYTHONHASHSEED)."),
    verbose: bool = typer.Option(False, help="Log detalhado"),
):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="%(levelname)s %(name)s: %(message)s")

    run_pipeline(
        input_path=input,
        dataset=dataset,
        output_dir=output_dir,
        model_dir=model_dir,
        skip_judge=skip_judge,
        threshold=threshold,
        evaluate=evaluate,
        use_kb=use_kb,
        max_llm_calls=max_llm_calls,
        seed=seed,
    )


if __name__ == "__main__":
    app()
