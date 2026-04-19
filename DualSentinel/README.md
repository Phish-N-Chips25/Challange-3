# MEIA Challenge 3 — SLM + LLM-as-a-Judge for Log Anomaly Detection

Pipeline de deteção de anomalias em logs Windows Sysmon/ETW usando:

- **SLMs** (IsolationForest, GRU) como detectores de primeira linha
- **SLM Analyst** (Phi-3 Medium via Ollama local) para pré-diagnóstico rápido por janela
- **LLM-as-a-Judge** (Llama 3.1 via Ollama local) para validação final com mapeamento ATT&CK e scoring

## Arquitetura

```
Logs (EVTX/CSV)
    ↓
Preprocessor      → parse + windowing (60s) + feature engineering
    ↓
SLM Detectors     → IsolationForest (anomaly score) + GRU (sequence) + Rule tagger (ATT&CK)
    ↓ [janelas score > threshold]
SLM Analyst       → Phi-3 Medium (Ollama local) → pré-diagnóstico: score, técnicas suspeitas, indicadores
    ↓ [pré-diagnóstico como hipótese]
LLM Judge         → Llama 3.1 (Ollama local) → valida/refuta pré-diagnóstico + ATT&CK + score final
    ↓
Results           → results/YYYY-MM-DD_HH-MM/ (JSON + Markdown report)
```

## Datasets suportados

| Dataset            | Tipo                       | Uso                   |
| ------------------ | -------------------------- | --------------------- |
| Splunk Attack Data | Sysmon/ATT&CK labels       | Avaliação de técnicas |
| LMD-2023           | Sysmon Lateral Movement    | Treino + avaliação LM |
| SILRAD             | Sysmon ransomware + benign | Stress test           |
| Logs pessoais      | Sysmon baseline (normal)   | Treino one-class      |

## Setup

```bash
git clone <repo>
cd meia-challenge3

python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

pip install -r requirements.txt

# Instalar e arrancar o Ollama
# https://ollama.com/download
ollama pull phi3:medium          # SLM Analyst (~8 GB)
ollama pull llama3.1             # LLM Judge   (~5 GB, versão 8B)
# ollama pull llama3.1:70b       # versão maior se tiveres VRAM suficiente

cp .env.example .env
# Editar .env conforme necessário (ver secção Configuração abaixo)
```

## Uso rápido

```bash
# Garantir que o Ollama está a correr
ollama serve   # em segundo plano

# Pipeline completo (SLM Analyst + LLM Judge)
python src/pipeline.py --input data/samples/sample_lmd.csv --dataset lmd

# Saltar o passo LLM (só detecção heurística)
python src/pipeline.py --input data/samples/sample_lmd.csv --dataset lmd --skip-judge

# Sobrepor o threshold sem alterar o .env
python src/pipeline.py --input data/samples/sample_lmd.csv --dataset lmd --threshold 0.4

# Só pre-processar
python src/preprocessor.py --input data/samples/sample_lmd.csv --output results/windows.json

# Correr apenas o SLM Analyst numa janela já processada
python src/slm_analyst.py --input results/windows_scored.json

# Correr apenas o LLM Judge num ficheiro de janelas já processadas
python src/llm_judge.py --input results/windows_scored.json

# Avaliação com métricas
python src/pipeline.py --input data/samples/sample_lmd.csv --dataset lmd --evaluate
python src/pipeline.py --input "data/samples/LMD-2023 [1.75M Elements - Normal]checked.csv" --dataset lmd --evaluate

# Avaliação rápida limitando o nº de chamadas ao Ollama (smoke test)
python src/pipeline.py --input "data/samples/LMD-2023 [1.75M Elements - Normal]checked.csv" --dataset lmd --evaluate --max-llm-calls 20
```

## Estrutura de ficheiros

```
src/
  preprocessor.py   Parser EVTX/CSV, windowing, feature engineering (112 dims)
  embeddings.py     Tokenizers field-aware + hash embeddings + smart features + BenignBaseline
  chains.py         Reconstrução de process chains parent→child
  detectors.py      ATT&CK rule tagger + KB hybrid retrieval + heuristic scorer
  attack_kb.py      Wrapper Chroma + BM25 (RRF) sobre a KB local
  slm_analyst.py    Phi-3 Medium (Ollama local) — pré-diagnóstico por janela
  llm_judge.py      Llama 3.1 (Ollama local) — validação final + ATT&CK + score
  pipeline.py       Orquestrador: liga todos os módulos
  utils.py          Helpers (logging, serialização, métricas, build_evidence_pack)
prompts/
  evidence_pack.md  Template do evidence pack enviado ao judge
  judge_rubric.md   Rubrica de scoring para o LLM judge
results/
  slm_analyses.json      Pré-diagnósticos do Phi-3 por janela
  windows_scored.json    Janelas com scores dos detectores
  judge_results.json     Resultados finais do Llama 3.1
  report_*.md            Relatório Markdown
notebooks/          EDA e análise de resultados
```

## Configuração (.env)

```
# Modelos Ollama
SLM_MODEL=phi3:medium        # SLM Analyst (pré-diagnóstico)
JUDGE_MODEL=llama3.1         # LLM Judge (validação final); usar llama3.1:70b para mais precisão

# Thresholds do pipeline
ANOMALY_THRESHOLD=0.6        # detector score acima do qual a janela vai ao SLM+Judge
                             # (sobreposto por --threshold na CLI)
WINDOW_SIZE_SECONDS=60       # tamanho das janelas temporais
MAX_EVENTS_PER_WINDOW=200    # limite de eventos por janela
```

## Opções da CLI

| Opção | Tipo | Default | Descrição |
| --- | --- | --- | --- |
| `--input` | path | — | CSV ou EVTX de input |
| `--dataset` | str | `lmd` | Schema do CSV: `lmd`, `splunk`, `silrad` |
| `--output-dir` | path | `results/YYYY-MM-DD_HH-MM` | Directório de output |
| `--model-dir` | path | — | (reservado para uso futuro) |
| `--skip-judge` | flag | off | Salta SLM Analyst + LLM Judge |
| `--threshold` | float | `.env` | Sobrepõe `ANOMALY_THRESHOLD` (default 0.6) |
| `--use-kb / --no-use-kb` | flag | on | Augmenta o tagger com retrieval da KB ATT&CK |
| `--max-llm-calls` | int | — | Limita chamadas ao Ollama em cada estágio LLM (SLM e Judge). Útil para smoke tests. |
| `--evaluate` | flag | off | Calcula métricas (requer coluna `label` no CSV) |
| `--seed` | int | 42 | Seed global (numpy + random + PYTHONHASHSEED + torch) para reprodutibilidade |
| `--verbose` | flag | off | Log detalhado (DEBUG) |

## Artefactos por execução

Cada run grava em `results/YYYY-MM-DD_HH-MM/`:

| Ficheiro | Conteúdo |
| --- | --- |
| `windows_scored.json` | Janelas com features, hits ATT&CK e `detector_score` |
| `chains.json` | Cadeias de processo extraídas |
| `evidence_packs.json` | Evidence packs sanitizados enviados ao SLM/Judge |
| `slm_analyses.json` | Pré-diagnóstico Phi-3 (1º sentinel) |
| `judge_results.json` | Veredicto Llama 3.1 (2º sentinel) |
| `report_<dataset>_<ts>.md` | Relatório Markdown legível |
| `metrics.json` | Precision/recall/F1, ROC-AUC, PR-AUC, matriz de confusão, métricas multi-label por técnica MITRE (só com `--evaluate`) |
| `telemetry.json` | Latência + token counts de cada chamada Ollama |
| `run_manifest.json` | Provenance: SHA-256 do input, modelos, seed, threshold, git commit, plataforma |

## Testes

```bash
python -m pytest DualSentinel/tests -q
```

Cobre: sanitização de prompt-injection, scorer heurístico (boundary cases),
métricas (perfect/random predictor), schema dedup, reprodutibilidade do seed,
agregação de telemetria e estrutura do `run_manifest.json`.

## Referências

- Smiliotopoulos & Kambourakis '23 — ExtraTrees + LMD-2023 (AUC 0.9984)
- Ispahany et al. '25 — iCNN-LSTM+ ransomware (F1 0.9961)
- Datasets: splunk/attack_data, OTRF/Security-Datasets, LMD Collections, SILRAD
