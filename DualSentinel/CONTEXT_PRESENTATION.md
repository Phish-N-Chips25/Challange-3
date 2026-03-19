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
  → Parse e normalização de campos Sysmon
  → Janelas temporais fixas de 60 segundos
  → 17 features por janela (contagens, entropias, flags)
        │
        ▼
[ 1.º Sentinela — Detectores Clássicos ]
  → IsolationForest: anomaly score por janela (não supervisionado)
  → GRU Autoencoder: erro de reconstrução em sequências de 10 janelas
  → ATT&CK Rule Tagger: regras determinísticas por técnica
  → Ensemble: 0.5×IF + 0.3×GRU + 0.2×Rules
        │  (só janelas com score ≥ threshold)
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
- Normalização de nomes de colunas para um schema canónico (`timestamp`, `event_id`, `process_name`, etc.).
- Fallback automático de `utctime` para `systemtime` quando o campo principal está corrompido (como no LMD-2023 Normal).
- Filtragem para EventIDs relevantes: 1, 3, 5, 6, 7, 8, 10, 11, 12, 13, 15, 16, 17, 18, 22, 23, 25.
- Feature engineering por janela: contagens de eventos, processos suspeitos, portas de lateral movement, entropias de Shannon, IPs únicos.

### 4.2 IsolationForest

Modelo one-class não supervisionado: não precisa de dados rotulados. Treina sobre os próprios dados de input (assumindo 5% de contaminação) e normaliza os scores para [0,1]. É a âncora principal do ensemble (peso 0.5).

### 4.3 GRU Autoencoder

Modelo PyTorch que aprende a reconstruir sequências de 10 janelas consecutivas. Alto erro de reconstrução indica que a janela quebra o padrão temporal — útil para detetar movimentos laterais lentos. Threshold automático no percentil 95 do treino.

### 4.4 ATT&CK Rule Tagger

Regras determinísticas mapeadas a técnicas MITRE (T1059.001 PowerShell, T1003 Credential Dumping, T1486 Ransomware, etc.). Corre sempre, mesmo quando os detectores ML são desligados com `--skip-detectors`.

### 4.5 SLM Analyst (Phi-3 Medium)

Recebe o *evidence pack* da janela (metadata + até 50 eventos resumidos + hits das regras). Produz um pré-diagnóstico estruturado em JSON com score preliminar, técnicas suspeitas e indicadores. Usa `format="json"` da API Ollama para forçar output válido.

### 4.6 LLM Judge (Llama 3.1)

Recebe o mesmo evidence pack + o pré-diagnóstico do Phi-3 como hipótese. Valida cada claim com referências explícitas aos eventos. Produz score final 0-10, veredicto (normal/suspicious/malicious), mapeamento ATT&CK com evidências, e risco de falso positivo. Usa rubrica de scoring injetada no system prompt.

---

## 5. Decisões de Design

| Decisão | Justificação |
|---|---|
| Janelas de 60 segundos | Granularidade natural para ataques; compromisso entre contexto e velocidade |
| IsolationForest one-class | Não requer labels; adapta-se ao dataset de input |
| Ensemble ponderado | IF mais fiável; GRU captura padrões temporais; regras são conservadoras |
| Dois LLMs em cadeia | Reduz alucinações; o Judge tem uma hipótese para validar, não parte do zero |
| Todos os LLMs locais (Ollama) | Dados sensíveis não saem da máquina; sem custos de API; reprodutível offline |
| `format="json"` na API Ollama | Decoding constrained; elimina respostas em prosa ou vazias |
| `--skip-detectors` + `--threshold` | Flexibilidade para comparar modos: IForest+GRU vs só rule tagger |

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
- `windows_scored.json` — todas as janelas com scores dos detectores
- `slm_analyses.json` — pré-diagnósticos do Phi-3 por janela
- `judge_results.json` — veredictos finais do Llama 3.1
- `report_<dataset>_<ts>.md` — relatório Markdown com sumário, técnicas top-10, janelas de alto risco

A avaliação quantitativa (`--evaluate`) requer a coluna `label` no CSV e calcula métricas de deteção por janela. A avaliação qualitativa consiste em verificar se os LLMs produzem diagnósticos fundamentados em evidências reais do log (anti-alucinação).

---

## 8. Relevância e Contribuição

Este trabalho contribui com:

1. **Pipeline integrado** que combina deteção clássica (sem labels) com análise semântica por LLMs — abordagem não explorada na literatura revista.
2. **Cadeia SLM→LLM** como estratégia anti-alucinação aplicada a cibersegurança.
3. **Mapeamento ATT&CK auditável** — cada técnica identificada inclui a evidência concreta do log que a suporta.
4. **Robustez a dados reais** — tratamento de timestamps corrompidos, schemas heterogéneos, e ficheiros de grande dimensão (1.75M eventos).
5. **Execução totalmente local** — sem dependências de APIs externas, compatível com ambientes de segurança isolados.
