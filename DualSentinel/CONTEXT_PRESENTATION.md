# DualSentinel — Contexto e Explicação para Apresentação

## 1. Problema

Os sistemas de deteção de intrusões (IDS) tradicionais baseados em regras têm uma limitação fundamental: **só detetam o que já foi descrito**. Face a ataques novos, variações de táticas conhecidas ou movimentos laterais subtis, falham frequentemente — gerando tanto falsos negativos (ameaças não detetadas) como falsos positivos (alertas espúrios que sobrecarregam os analistas).

O objetivo deste trabalho é construir um pipeline que combine **deteção estatística clássica** com **raciocínio semântico de modelos de linguagem locais** para identificar anomalias em logs Windows e mapeá-las para o quadro MITRE ATT&CK — sem depender de regras pré-escritas nem de APIs externas.

---

## 2. Contexto Académico (Estado da Arte)

O domínio de anomaly detection em logs Windows/Sysmon está bem estudado, mas com algumas lacunas importantes:

| Trabalho | Abordagem | Melhor Resultado |
|---|---|---|
| Smiliotopoulos & Kambourakis '23 | ExtraTrees sobre features Sysmon | AUC 0.9984, F1 0.9941 (LMD-2023) |
| Ispahany et al. '25 (IEEE Access) | CNN-LSTM incremental | F1 0.9961 (deteção de ransomware) |
| Ispahany et al. '25 (ArXiv / SILRAD) | Hoeffding ARF + ADWIN (streaming) | F1 0.9473 em tempo real |
| Achmad et al. '25 | LOF + IsolationForest + PCA | F1 0.9873 |

**Lacunas identificadas na literatura:**
- Os modelos clássicos dão scores mas não explicações — um analista SOC não sabe *porquê* foi gerado um alerta.
- Nenhum trabalho integra LLMs locais para gerar diagnósticos auditáveis por janela temporal.
- A maioria assume dados limpos e bem estruturados; poucos tratam timestamps corrompidos ou formatos heterogéneos.

O dataset primário usado neste trabalho é o **LMD-2023** (Smiliotopoulos & Kambourakis), com 1.75 milhões de eventos Sysmon de movimentos laterais simulados.

---

## 3. Proposta: DualSentinel

A ideia central é uma arquitetura de **dois sentinelas**:

```
Logs Windows (EVTX / CSV)
        │
        ▼
[ Pré-processamento ]
  → Parse e normalização de campos Sysmon (schema canónico de 23 colunas)
  → Janelas temporais fixas de 60 segundos
  → Process chains: reconstrução de cadeias parent→child por process_guid
  → Vetor de features por janela (112 dims):
        • 21 base (contagens por EID, entropias, flags)
        • 27 smart features semânticas (cmdline obfuscation, LOLBINs,
          base64 blobs, hive distribution, suspicious registry paths,
          path depth/temp/appdata, lateral port ratio, suspicious
          parent→child pairs, …)
        • 64 hash embeddings field-aware (cmdline / registry / process /
          path, mean-pool por janela, 16 dims cada)
  → Baseline self-supervised (centróide + token rarity por field) →
        sinais de desvio expostos ao LLM
        │
        ▼
[ 1.º Sentinela — Detecção Heurística ]
  → ATT&CK Rule Tagger: regras determinísticas por técnica (T1059, T1003, …)
  → Retrieval híbrido na KB local (ChromaDB + BM25 com Reciprocal Rank Fusion):
        candidatos a técnica MITRE com evidência textual
  → Smart-feature flags: obfuscation, LOLBINs, suspicious paths/registry,
        lateral port ratio, parent→child suspeitos
  → Baseline deviation: distância ao centróide + token rarity por field
  → Heuristic score ∈ [0, 1]: rule hits âncora (≥0.5) + KB candidates
        + smart flags + baseline deviation
        │  (só janelas com score ≥ threshold escalam)
        ▼
[ 2.º Sentinela — Análise por LLM local ]
  → SLM Analyst (Phi-3 Medium, ~8GB, Ollama):
      pré-diagnóstico rápido, score preliminar, técnicas suspeitas
  → LLM Judge (Llama 3.1 8B, ~5GB, Ollama):
      valida/refuta o pré-diagnóstico com referências explícitas a eventos
      mapeamento ATT&CK com evidências, score final 0-10, risco de FP
        │
        ▼
[ Resultados ]
  → JSON estruturado + Relatório Markdown por execução
```

**Por que dois LLMs e não um só?**

O padrão SLM→LLM é uma forma de *chain-of-thought* guiado: o Phi-3 é barato e rápido, e produz uma hipótese; o Llama 3.1 recebe essa hipótese como contexto e valida-a ou refuta-a com evidências concretas do pack de logs. Isto reduz alucinações porque o judge tem uma âncora — não parte de uma folha em branco.

---

## 4. Componentes Técnicos

### 4.1 Pré-processamento

- Suporte a ficheiros `.evtx` (binário Windows) e `.csv` (LMD-2023, Splunk Attack Data, SILRAD).
- Normalização de nomes de colunas para um **schema canónico de 23 campos** (`timestamp`, `event_id`, `process_name`, `command_line`, `registry_key`, `network_dest_port`, etc.). Síntese de `process_guid` quando o dataset não o fornece.
- Fallback automático de `utctime` para `systemtime` quando o campo principal está corrompido (como no LMD-2023 Normal).
- Filtragem para EventIDs relevantes: 1, 3, 5, 6, 7, 8, 10, 11, 12, 13, 15, 16, 17, 18, 22, 23, 25.
- **Process chains**: agrupamento de eventos por `process_guid` para reconstruir cadeias parent→child com timestamps e duração — fornecidas ao LLM como ordered timeline.

#### 4.1.1 Feature engineering por janela (vetor de 112 dims)

Cada janela é representada pela concatenação de três blocos:

| Bloco | Dims | Conteúdo |
|---|---|---|
| **Base** | 21 | Contagens por EventID, processos suspeitos, lateral movement port count, entropias de Shannon (event_id, process), flags (mimikatz, psexec) |
| **Smart features** | 27 | Indicadores semânticos derivados — não são counts brutos: obfuscation regex hits no cmdline, LOLBIN calls (certutil, mshta, …), base64 blobs longos, flag density, hive distribution (HKLM/HKCU), suspicious registry subpaths (Run, Winlogon, IFEO, …), path depth, temp/appdata/system32 ratios, executable writes, lateral port ratio, suspicious parent→child pairs (ex.: `winword.exe → powershell.exe`) |
| **Field-aware embeddings** | 64 | `HashingVectorizer` (sklearn, sem dependências externas) sobre cada campo — command_line, registry_key, process_name, file_path — tokenizadores próprios por campo (paths splitados, hives canonicalizados, ports categorizadas em well_known/registered/dynamic/lateral). Mean-pool por janela + sum-bucket reduction para 16 dims cada |

Acima do vetor, a janela é **anotada com sinais de baseline self-supervised** (não fazem parte do feature vector, mas são entregues ao LLM):

- Distância do embedding ao centróide médio das janelas (proxy para "este conjunto destoa do bulk").
- Token rarity ratio por campo: fração de tokens nesta janela que apareceram ≤1 vez na baseline (`cmdline_rare_token_ratio`, `registry_rare_token_ratio`, …).

A premissa benigna é a mesma do IsolationForest (contaminação ~5%); quando há labels, o `fit()` aceita máscara para refinar.

### 4.2 Heuristic Scorer

Funde quatro sinais num único `detector_score ∈ [0, 1]` que decide se a janela escala para a fase LLM:

| Sinal | Peso/Limite | Justificação |
|---|---|---|
| **Rule hits** (regras determinísticas) | âncora ≥0.5 + 0.4×max(confidence) | Sinal auditado, não probabilístico |
| **KB candidates** (retrieval híbrido) | +0.05 por hit, cap 0.15 | Retrieval ≠ confirmação |
| **Smart-feature flags** (7 indicadores) | +0.08 por flag ativa | obfuscation, LOLBINs, base64 blobs, suspicious paths/registry, lateral ports, parent→child |
| **Baseline deviation** | +0.15×emb_dist + 0.10×max rare ratio | Capta janelas novas que nenhuma regra dispara |

Optação consciente por **não usar IsolationForest nem GRU**: esses modelos clássicos não trazem ganho útil sobre o sinal já codificado nas regras MITRE + smart features + baseline (verificado empiricamente nos datasets), e produzem um score numérico opaco que o LLM Judge não pode auditar. Cada componente do score heurístico é inspecionável — alinhado com o objetivo de gerar diagnósticos auditáveis.

### 4.3 ATT&CK Rule Tagger + KB Híbrida

Duas fontes de candidatos a técnica MITRE, fundidas no evidence pack:

1. **Regras determinísticas** mapeadas a técnicas MITRE (T1059.001 PowerShell, T1003 Credential Dumping, T1486 Ransomware, etc.). Apresentadas ao LLM como *confirmadas*.
2. **Retrieval híbrido na KB local** (ChromaDB + BM25, fundidos por Reciprocal Rank Fusion sobre 3463 entradas indexadas — Atomic Red Team, Sigma rules, ATT&CK descriptions). Apresentadas ao LLM como *candidatos não confirmados*, com a evidência textual que justificou a recuperação.

Esta separação "confirmado vs candidato" é deliberada: o Judge pode descartar candidatos sem fundamento sem inflacionar falsos positivos.

### 4.4 SLM Analyst (Phi-3 Medium)

Recebe o *evidence pack* da janela com metadata, contagens base, **smart features ativos** (cmdline obfuscation, LOLBINs, suspicious paths…), **desvios à baseline** (distância ao centróide, rare token ratios), hits de regras, candidatos da KB, **peak process chain** ordenada cronologicamente, e até 50 eventos resumidos. Produz um pré-diagnóstico estruturado em JSON com score preliminar, técnicas suspeitas e indicadores. Usa `format="json"` da API Ollama para forçar output válido.

### 4.5 LLM Judge (Llama 3.1)

Recebe o mesmo evidence pack + o pré-diagnóstico do Phi-3 como hipótese. Valida cada claim com referências explícitas aos eventos. Produz score final 0-10, veredicto (normal/suspicious/malicious), mapeamento ATT&CK com evidências, e risco de falso positivo. Usa rubrica de scoring injetada no system prompt.

---

## 5. Decisões de Design

| Decisão | Justificação |
|---|---|
| Janelas de 60 segundos | Granularidade natural para ataques; compromisso entre contexto e velocidade |
| Heuristic scorer (rules + smart features + baseline) em vez de IsolationForest/GRU | Cada termo é auditável pelo Judge; modelos clássicos opacos não acrescentam ganho útil sobre os sinais codificados |
| Baseline self-supervised | Capta janelas novas sem regras; não requer labels; mesma premissa de bulk-of-windows que IForest assumia |
| Dois LLMs em cadeia | Reduz alucinações; o Judge tem uma hipótese para validar, não parte do zero |
| Todos os LLMs locais (Ollama) | Dados sensíveis não saem da máquina; sem custos de API; reprodutível offline |
| `format="json"` na API Ollama | Decoding constrained; elimina respostas em prosa ou vazias |
| KB híbrida (Chroma + BM25, RRF) | Combina semântica densa com matching exato de tokens raros; sem dependências externas |

---

## 6. Datasets

| Dataset | Tipo | Utilização |
|---|---|---|
| LMD-2023 (Smiliotopoulos '23) | Sysmon, 1.75M eventos, lateral movement simulado | Avaliação principal |
| Splunk Attack Data | Sysmon com labels ATT&CK | Avaliação de técnicas |
| SILRAD | Sysmon ransomware + benigno | Stress test |

---

## 7. Resultados Esperados e Avaliação

Para cada execução o pipeline gera:
- `windows_scored.json` — todas as janelas com scores dos detectores, smart features, baseline deviation, ATT&CK hits e peak chain
- `chains.json` — todas as process chains reconstruídas
- `evidence_packs.json` — packs renderizados para janelas acima do threshold (debug aid e auditoria)
- `slm_analyses.json` — pré-diagnósticos do Phi-3 por janela
- `judge_results.json` — veredictos finais do Llama 3.1
- `report_<dataset>_<ts>.md` — relatório Markdown com sumário, técnicas top-10, janelas de alto risco

A avaliação quantitativa (`--evaluate`) requer a coluna `label` no CSV e calcula métricas de deteção por janela. A avaliação qualitativa consiste em verificar se os LLMs produzem diagnósticos fundamentados em evidências reais do log (anti-alucinação).

---

## 8. Relevância e Contribuição

Este trabalho contribui com:

1. **Pipeline integrado** que combina deteção clássica (sem labels) com análise semântica por LLMs — abordagem não explorada na literatura revista.
2. **Cadeia SLM→LLM** como estratégia anti-alucinação aplicada a cibersegurança.
3. **Feature engineering field-aware** para Sysmon: tokenizadores e embeddings por campo (cmdline, registry, process, path, ports) + 27 features semânticas que vão para além de counts e entropias, incluindo baseline self-supervised de raridade de tokens e distância ao centróide.
4. **Mapeamento ATT&CK auditável com retrieval híbrido** — cada técnica identificada inclui a evidência concreta do log; KB local (ChromaDB + BM25, RRF) separa hits confirmados de candidatos.
5. **Robustez a dados reais** — tratamento de timestamps corrompidos, schemas heterogéneos, e ficheiros de grande dimensão (1.75M eventos).
6. **Execução totalmente local** — sem dependências de APIs externas, compatível com ambientes de segurança isolados.
