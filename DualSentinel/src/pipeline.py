"""
pipeline.py
Orquestrador principal do Challenge 3 MEIA.

Fluxo:
  1. Parse + windowing (preprocessor)
  2. Feature extraction
  3. IsolationForest + GRU scoring (detectors)
  4. ATT&CK rule tagging
  5. LLM judge nas janelas de alto risco
  6. Geração de relatório Markdown
"""

import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Optional

import numpy as np
import typer
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table

# load_dotenv MUST run before local imports so module-level os.getenv() calls
# in slm_analyst.py and llm_judge.py pick up .env values.
load_dotenv()

from preprocessor import make_windows, parse_csv, parse_evtx, WindowFeatures
from detectors import IForestDetector, GRUDetector, tag_techniques, ensemble_score
from llm_judge import LLMJudge, JudgeResult
from slm_analyst import SLMAnalyst
console = Console()
logger = logging.getLogger(__name__)

ANOMALY_THRESHOLD = float(os.getenv("ANOMALY_THRESHOLD", 0.6))
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
    evaluate: bool = False,
) -> dict:
    """
    Pipeline completo. Devolve dict com resultados e caminhos de output.
    """
    ts = datetime.now().strftime("%Y-%m-%d_%H-%M")
    if output_dir is None:
        output_dir = Path("results") / ts
    output_dir.mkdir(parents=True, exist_ok=True)

    # ── 1. Parse ──────────────────────────────
    console.print(f"[bold]Step 1:[/bold] Parsing {input_path.name}...")
    if input_path.suffix.lower() == ".evtx":
        df = parse_evtx(input_path)
    else:
        df = parse_csv(input_path, dataset=dataset)

    if df.empty:
        console.print("[red]Erro: nenhum evento carregado.")
        return {}

    # ── 2. Windowing ──────────────────────────
    console.print(f"[bold]Step 2:[/bold] Windowing ({WINDOW_SIZE}s)...")
    windows: list[WindowFeatures] = list(
        make_windows(df, window_size_seconds=WINDOW_SIZE, max_events=MAX_EVENTS)
    )
    console.print(f"  → {len(windows)} janelas criadas")

    # Feature matrix
    X = np.array([w.to_feature_vector() for w in windows])

    # ── 3. IsolationForest ────────────────────
    console.print("[bold]Step 3:[/bold] IsolationForest scoring...")
    model_path = (model_dir or output_dir) / "iforest.pkl"

    if model_dir and (model_dir / "iforest.pkl").exists():
        iforest = IForestDetector.load(model_dir / "iforest.pkl")
        console.print("  → Modelo carregado de disco")
    else:
        iforest = IForestDetector()
        iforest.fit(X)
        iforest.save(model_path)

    if_scores = iforest.score(X)

    # ── 4. GRU (opcional, só se há janelas suficientes) ──
    gru_scores = np.zeros(len(windows))
    seq_len = 10
    if len(windows) >= seq_len + 1:
        console.print("[bold]Step 4:[/bold] GRU sequence scoring...")
        gru = GRUDetector(feature_dim=X.shape[1], seq_len=seq_len)
        sequences = np.array([X[i:i+seq_len] for i in range(len(X) - seq_len)])
        gru.fit(sequences)
        gru_raw = gru.score(sequences)
        # Normalizar e alinhar com janelas (padding do início)
        if gru_raw.max() > 0:
            gru_norm = gru_raw / gru_raw.max()
        else:
            gru_norm = gru_raw
        gru_scores[seq_len:] = gru_norm
    else:
        console.print("[dim]Step 4: GRU skipped (janelas insuficientes)[/dim]")

    # ── 5. Rule tagging + ensemble score ──────
    console.print("[bold]Step 5:[/bold] ATT&CK rule tagging + ensemble score...")
    window_dicts = []
    for i, w in enumerate(windows):
        wd = w.to_dict()
        wd["attck_hits"] = tag_techniques(wd)
        wd["if_score"] = float(if_scores[i])
        wd["gru_score"] = float(gru_scores[i])
        wd["detector_score"] = ensemble_score(
            iforest_score=float(if_scores[i]),
            gru_score=float(gru_scores[i]),
            has_attck_hits=len(wd["attck_hits"]) > 0,
        )
        window_dicts.append(wd)

    # Guardar janelas enriquecidas
    windows_path = output_dir / "windows_scored.json"
    with open(windows_path, "w") as f:
        json.dump(window_dicts, f, indent=2, default=str)

    high_risk_count = sum(1 for w in window_dicts if w["detector_score"] >= ANOMALY_THRESHOLD)
    console.print(f"  → {high_risk_count}/{len(window_dicts)} janelas acima do threshold ({ANOMALY_THRESHOLD})")

    # ── 6. SLM Analyst (Phi-3) + LLM Judge (Llama 3.1) ──
    judge_results: list[JudgeResult] = []
    if not skip_judge:
        # ── 6a. SLM pre-diagnosis (Phi-3 Medium) ──
        slm_analyses = []
        try:
            console.print(
                f"[bold]Step 6a:[/bold] SLM pre-diagnosis "
                f"({os.getenv('SLM_MODEL', 'phi3:medium')})..."
            )
            analyst = SLMAnalyst()
            slm_analyses = analyst.analyse_batch(window_dicts, threshold=ANOMALY_THRESHOLD)
            console.print(f"  → {len(slm_analyses)} janelas pré-diagnosticadas pelo SLM")

            slm_path = output_dir / "slm_analyses.json"
            with open(slm_path, "w") as f:
                json.dump([a.to_dict() for a in slm_analyses], f, indent=2, default=str)
        except Exception as e:
            console.print(f"[yellow]SLM analyst skipped: {e}[/yellow]")

        # ── 6b. LLM Judge final validation (Llama 3.1) ──
        try:
            console.print(
                f"[bold]Step 6b:[/bold] LLM judge validation "
                f"({os.getenv('JUDGE_MODEL', 'llama3.1')})..."
            )
            judge = LLMJudge()
            judge_results = judge.judge_batch(
                window_dicts,
                slm_analyses=slm_analyses if slm_analyses else None,
                threshold=ANOMALY_THRESHOLD,
                max_windows=50,
            )

            judge_path = output_dir / "judge_results.json"
            with open(judge_path, "w") as f:
                json.dump([r.to_dict() for r in judge_results], f, indent=2, default=str)
            console.print(f"  → {len(judge_results)} janelas validadas pelo judge")
        except Exception as e:
            console.print(f"[yellow]LLM judge skipped: {e}[/yellow]")
    else:
        console.print("[dim]Step 6: SLM + LLM judge skipped (--skip-judge)[/dim]")

    # ── 7. Relatório ──────────────────────────
    console.print("[bold]Step 7:[/bold] Generating report...")
    report_path = generate_report(window_dicts, judge_results, output_dir, dataset)

    # ── 8. Métricas (se --evaluate) ───────────
    if evaluate and "label" in df.columns:
        console.print("[bold]Step 8:[/bold] Computing metrics...")
        _print_metrics(window_dicts, df)

    # Sumário final
    console.print("")
    table = Table(title="Pipeline complete", show_header=True)
    table.add_column("Output", style="cyan")
    table.add_column("Path")
    table.add_row("Windows scored", str(windows_path))
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
    """Métricas básicas se existirem labels no dataset."""
    console.print("  (métricas detalhadas requerem labels por evento — disponível no notebook)")


# ─────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────

app = typer.Typer()

@app.command()
def main(
    input: Path = typer.Argument(..., help="CSV ou EVTX de input"),
    dataset: str = typer.Option("lmd", help="Formato: lmd, splunk, silrad"),
    output_dir: Optional[Path] = typer.Option(None, help="Directório de output"),
    model_dir: Optional[Path] = typer.Option(None, help="Directório com modelos pré-treinados"),
    skip_judge: bool = typer.Option(False, help="Salta o LLM judge (economiza tokens)"),
    evaluate: bool = typer.Option(False, help="Calcula métricas (requer labels)"),
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
        evaluate=evaluate,
    )


if __name__ == "__main__":
    app()
