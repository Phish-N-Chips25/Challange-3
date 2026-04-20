# Challenge 3 — Project Summary
## Integrated Physical Access Control & Cyber Threat Management

---

## A História

Imagina um analista SOC que chega ao trabalho de manhã.
Antes de poder abrir o dashboard de ameaças, o sistema precisa de saber **quem ele é**.
Não uma password — uma password pode ser roubada. **O rosto dele.**

Depois de autenticado, entra num mundo onde milhões de eventos de sistema Windows foram analisados em tempo real por modelos de machine learning treinados para encontrar o que nenhuma regra consegue descrever: **comportamento anómalo**.

E quando uma ameaça é detetada, o sistema não se limita a lançar um alerta.
Ele **raciocina** — liga os pontos, consulta a base de conhecimento do MITRE ATT&CK, e diz ao analista exatamente qual técnica de ataque foi usada, com evidências concretas.

Este é o Challenge 3.

---

## O Problema

Os sistemas de deteção de intrusões tradicionais baseados em regras têm uma falha fundamental:
**só detetam o que já foi descrito antes.**

Face a variações táticas, movimentos laterais subtis ou ataques de dia zero, falham — gerando alertas espúrios que sobrecarregam analistas, ou pior, silêncio quando há uma intrusão real.

O objetivo deste projeto é construir um sistema end-to-end que:
1. Garante acesso físico seguro através de reconhecimento facial
2. Deteta anomalias em logs Windows Sysmon sem depender de regras pré-escritas
3. Mapeia automaticamente as ameaças para técnicas MITRE ATT&CK com explicações auditáveis

---

## Os Três Pilares

### Pilar 1 — Quem és tu? (Reconhecimento Facial)

**Módulo:** `frontend/` + `RNAAPIA/`

O acesso ao sistema começa pela câmera. O modelo **InsightFace (buffalo_sc)** extrai embeddings faciais de alta dimensão usando ArcFace — o mesmo princípio usado em sistemas biométricos de nível profissional.

Cada frame capturado é comparado com os embeddings das pessoas registadas via **similaridade coseno**. Se o score mantiver-se acima de **0.70** durante o tempo de observação, o utilizador é autenticado e redireccionado para o SOC dashboard.

**Dados técnicos:**
- Modelo: InsightFace buffalo_sc (ArcFace + RetinaFace)
- Threshold: cosine similarity ≥ 0.70
- Utilizadores registados: 5 pessoas da organização
- Fine-tuning organizacional: CNN + ResNet-50 treinados e avaliados com métricas FAR/FRR/EER

**Evolução da arquitetura:**
O módulo RNAAPIA documentou toda a jornada de treino — desde uma baseline em Kaggle até ao fine-tuning com data augmentation (~20x por foto) especificamente para as 5 pessoas da organização, com modelos guardados para deployment.

---

### Pilar 2 — Algo está errado? (Deteção de Anomalias)

**Módulo:** `cyber-anomaly-detection/` (10 notebooks de investigação)

A deteção de ameaças funciona em duas camadas sobre logs Windows Sysmon:

#### Camada 1 — Sequence TransformerAE (deteção de chains suspeitas)

O sistema processa eventos Sysmon em janelas de 45 eventos consecutivos, convertidos em embeddings **Word2Vec 352-dim**. Um **Transformer Autoencoder** (NAS+HPO via Optuna) aprendeu a reconstruir comportamento benigno — quando o erro de reconstrução ultrapassa o threshold **0.627528**, a chain é sinalizada como suspeita.

- Treinado 100% de forma não supervisionada em 2.3M eventos benignos (LMD-2023)
- AP = 0.814 em OTRF Atomic Red Team | AP = 0.836 em Splunk Attack Range
- Arquitetura: hidden=256, latent=128, 2 layers, 8 heads (descoberta por Optuna)

#### Camada 2 — Single-event Autoencoder (scoring por evento)

Dentro de cada chain sinalizada, cada evento individual é pontuado por um **Autoencoder de 4 camadas** `[353→231→176→162→8]` com ativação ELU. Isto permite identificar os eventos exatos mais anómalos — fornecendo ao analista uma vista cirúrgica da ameaça.

- AUC = 0.989–0.992 em avaliação cross-dataset (genuína generalização)
- Input: Word2Vec 353-dim por evento

**O caminho até aqui:** 10 notebooks documentam toda a investigação — desde EDA sobre 4 datasets (SILRAD, LMD-2023, OTRF, Splunk), passando por IsolationForest, KMeans, OCSVM, gradient boosting com CASH (Optuna), até chegar aos autoencoders como solução óptima.

---

### Pilar 3 — O que é? (Atribuição MITRE ATT&CK)

**Módulo:** `cyber-anomaly-detection/` (Notebook 10) + `DualSentinel/`

Detetar que algo é anómalo não chega. Um analista precisa de saber **o quê e porquê**.

#### RAG Híbrido + LLM (sistema principal)

Uma base de conhecimento com **3.463 entradas** foi construída a partir de:
- MITRE STIX (técnicas ATT&CK oficiais)
- OTRF metadata (contexto de exercícios Atomic Red Team)
- Splunk YAML (configurações de deteção)
- Sigma rules (regras de hunting)

A retrieval combina **dense search** (all-mpnet-base-v2 via ChromaDB) com **BM25 sparse search** — hybrid RAG para maximizar recall.

O contexto recuperado é enviado ao **Qwen 2.5 32B via Ollama** com um prompt chain-of-thought estruturado:
1. Observar os eventos
2. Fazer match com a técnica
3. Produzir JSON com ID da técnica, confiança e explicação

**RAG recall: 60% em OTRF Atomic Red Team**

#### DualSentinel — Abordagem Alternativa Leve (Auditável)

Uma segunda abordagem foi desenvolvida em paralelo para contextos com menos recursos computacionais e com requisitos fortes de auditabilidade:

```
Heuristic Scorer (ATT&CK rules + smart features + baseline + KB hybrid)
        → SLM Analyst (Phi-3 Medium)
        → LLM Judge (Llama 3.2)
```

A arquitetura clássica baseada em IsolationForest + GRU foi **substituída por um heuristic scorer** em que cada termo é inspecionável (regras ATT&CK confirmadas, 7 smart-feature flags, desvio à baseline self-supervised, hits da KB hybrid Chroma+BM25 com RRF). Testes empíricos no LMD-2023 e Splunk Attack Data mostraram que os modelos opacos não traziam ganho mensurável e impediam o LLM Judge de auditar a evidência.

O padrão **SLM→LLM** é uma forma de chain-of-thought guiado: o Phi-3 Medium produz uma hipótese rápida; o Llama 3.2 valida-a ou refuta-a com referências explícitas aos eventos. Isto reduz alucinações porque o judge tem uma âncora — não parte de uma folha em branco.

**Todos os LLMs correm localmente via Ollama** — dados sensíveis não saem da máquina.

**Defesa académica do DualSentinel:** 4 notebooks consolidados em [DualSentinel/notebooks/](DualSentinel/notebooks/):
- [defesa_lmd_full_report.ipynb](DualSentinel/notebooks/defesa_lmd_full_report.ipynb) — corrida full-stack do pipeline em LMD-2023 com export HTML (17 secções)
- [threshold_calibration.ipynb](DualSentinel/notebooks/threshold_calibration.ipynb) — calibração empírica do threshold de decisão (sweep F1/Youden/FPR, ROC, PR) sobre as corridas EoRS/EoHT do LMD-2023
- [kb_ablation.ipynb](DualSentinel/notebooks/kb_ablation.ipynb) — ablação on/off da KB hybrid retrieval
- [eda.ipynb](DualSentinel/notebooks/eda.ipynb) — exploração dos datasets de input

---

## O Sistema Integrado

O `frontend/app.py` liga os três pilares numa aplicação Flask coesa:

```
Câmera → InsightFace → Autenticação → SOC Dashboard
                                            │
                              ┌─────────────┴──────────────┐
                              ▼                            ▼
                    Fila de ameaças              Status dos modelos
                    (OTRF / Splunk)              (AE + TransformerAE
                              │                  + ATT&CK KB + Ollama)
                              ▼
                    Selecionar chain suspeita
                              │
                   ┌──────────┴───────────┐
                   ▼                      ▼
         Scores da sequência       Scores por evento
         (TransformerAE)           (Single-event AE)
                   │
                   ▼
         Atribuição ATT&CK
         (RAG + Qwen 2.5 32B)
                   │
                   ▼
         Técnica ID + confiança + explicação
```

---

## Números que Contam

| Componente | Métrica | Valor |
|---|---|---|
| Autenticação facial | Threshold cosine similarity | 0.70 |
| TransformerAE (sequências) | AP em OTRF Atomic | **0.814** |
| TransformerAE (sequências) | AP em Splunk Attack Range | **0.836** |
| Single-event AE | AUC cross-dataset | **0.989–0.992** |
| ATT&CK KB | Entradas indexadas | **3.463** |
| RAG attribution | Recall em OTRF | **60%** |
| Dados de treino | Eventos Sysmon benignos | **2.3M** |
| Datasets avaliados | OTRF + Splunk | **~2.6M eventos** |
| T-codes com ground truth | OTRF + Splunk combinados | **230 técnicas** |

---

## O Que Nos Diferencia

| Abordagem tradicional | Challenge 3 |
|---|---|
| Regras pré-escritas | Aprendizagem não supervisionada — deteta o desconhecido |
| Alertas sem contexto | Atribuição ATT&CK com chain-of-thought e evidências |
| APIs externas (dados saem) | 100% local via Ollama — dados sensíveis nunca saem |
| Password ou smart card | Reconhecimento facial com ArcFace |
| Score binário (alerta/não alerta) | Score por evento + score de sequência + técnica + confiança |

---

## Jornada de Investigação (Os 10 Notebooks)

A solução final não nasceu do nada. O repositório documenta toda a evolução:

| Fase | Notebooks | O que foi investigado |
|---|---|---|
| **EDA** | 01–04 | 4 datasets, distribuições, anomalias nos dados, formatos heterogéneos |
| **Baseline** | 05 | IsolationForest, KMeans, OCSVM — estabelecer referências |
| **Optimização** | 06 | CASH com Optuna: XGBoost, LightGBM, CatBoost, AutoencoderAE (NAS+HPO) |
| **Sequências** | 07 | TransformerAE NAS+HPO, calibração do threshold |
| **Generalização** | 08 | Avaliação cross-dataset: LMD→OTRF→Splunk |
| **KB & RAG** | 09 | Construção da base MITRE, ChromaDB, BM25, indexação |
| **Atribuição** | 10 | Pipeline end-to-end RAG + Qwen 2.5 32B |

---

## Stack Tecnológico

**Reconhecimento Facial**
- InsightFace (ArcFace / RetinaFace), ONNX Runtime, facenet-pytorch, OpenCV

**Deteção de Anomalias**
- PyTorch (TransformerAE + Single-event AE), Word2Vec (gensim), scikit-learn
- Optuna (NAS + HPO), MLflow (experiment tracking)
- DualSentinel: heuristic scorer auditável (ATT&CK rules + smart features + self-supervised baseline)

**ATT&CK Attribution**
- ChromaDB (vector store), sentence-transformers (all-mpnet-base-v2), rank-bm25
- Ollama (Qwen 2.5 32B / phi4 / Llama 3.2 / Phi-3 Medium), Sigma rules, MITRE STIX

**Interface**
- Flask, HTML/CSS/JS (dashboard SOC), Streamlit (demo standalone)

**Infraestrutura**
- Conda (ambiente isolado Python 3.11 + CUDA 12.6), FastAPI, uvicorn

---

## Pontos de Ligação para a Narrativa do Pitch

1. **O problema é real** — Os analistas SOC afogam-se em alertas. A fadiga de alertas é uma das principais causas de incidentes não detetados.

2. **A porta de entrada** — Segurança começa no acesso físico. InsightFace garante que só quem deve, entra.

3. **A investigação foi séria** — 10 notebooks, 4 datasets, múltiplas arquiteturas testadas. Não foi a primeira ideia — foi a melhor depois de muitas iteradas.

4. **O modelo não alucina sem evidências** — A arquitectura RAG + chain-of-thought garante que o LLM fundamenta as suas conclusões em dados reais, não em probabilidade estatística.

5. **Privacidade by design** — Tudo corre localmente. Numa organização real, logs de sistema são dados sensíveis. Ollama local resolve este problema por design.

6. **Escalabilidade** — O DualSentinel mostra que o mesmo conceito funciona com modelos mais pequenos (Phi-3 Medium + Llama 3.2) sobre um heuristic scorer auditável, tornando a solução viável mesmo sem GPUs de topo e com cada decisão justificável perante um analista.
