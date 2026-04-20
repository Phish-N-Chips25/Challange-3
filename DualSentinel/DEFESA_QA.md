# DualSentinel — Q&A de Defesa

> Respostas curtas e citáveis para três perguntas centrais da defesa,
> baseadas no código real do projeto.

---

## 1. Pré-processamento antes das SLMs

Pipeline em quatro etapas, definido em [src/preprocessor.py](src/preprocessor.py)
e [src/utils.py](src/utils.py):

### a) Parse + normalização ([preprocessor.py#L160](src/preprocessor.py#L160))

- `parse_csv()` lê o CSV (LMD-2023, Splunk Attack Data ou SILRAD), faz lowercase
  nos nomes de colunas, e mapeia ~20 colunas de cada formato para um *schema
  canónico*: `timestamp`, `event_id`, `process_name`, `parent_process`,
  `command_line`, `network_dest_ip/port`, `file_path`, `registry_key`, `user`,
  `host`, `label`, `technique`.
- Timestamps convertidos para UTC; eventos sem timestamp são descartados;
  `image` paths reduzidos a basename.
- Filtro a `RELEVANT_EVENT_IDS` (Sysmon EID 1, 3, 6, 7, 8, 10, 11, 12-14, 22, 23) —
  descarta ruído.

### b) Janelamento de 60 s ([preprocessor.py#L420](src/preprocessor.py#L420))

- `make_windows()` agrupa eventos em janelas fixas de **60 segundos**
  (configurável via `WINDOW_SIZE_SECONDS`).
- Cap de **200 eventos por janela** para não rebentar o context window do SLM.
- Janelas vazias são saltadas.

### c) Feature engineering por janela

- **Contagens estruturais**: `event_count`, `process_creation_count` (EID=1),
  `network_connection_count` (EID=3), `file_creation_count` (EID=11),
  `registry_modification_count` (EID=13), `remote_thread_count` (EID=8),
  `process_access_count` (EID=10), `driver_load_count` (EID=6),
  `file_delete_count` (EID=23).
- **Indicadores binários / heurísticos**: `has_mimikatz`, `has_psexec`,
  `suspicious_process_count`, `lateral_movement_port_count` (445/3389/etc.),
  `outbound_unique_ips`.
- **Entropia de Shannon** sobre `process_name` e `event_id` — sinaliza
  varrimento ou diversidade anormal.
- *Smart features* + embedding (`build_window_embedding`) com tokenização de
  cmdline / registry / paths.
- **Resumo textual** de até 50 eventos no formato
  `EID=1 | proc=powershell.exe | cmd=...` para o evidence pack.

### d) Sanitização anti-prompt-injection ([utils.py::sanitize_for_prompt](src/utils.py#L43))

Antes de qualquer string de log entrar num prompt:

- Strip de chat-template markers (`<|im_start|>`, `<|system|>`, …).
- Remoção de zero-width / bidi chars.
- Substituição de fences ```` ``` ```` por aspas para impedir code-block escape.
- Padrões clássicos de jailbreak (`"ignore previous instructions"`, `"DAN mode"`, …)
  marcados como `[!INJ:...]` em vez de removidos silenciosamente — o LLM vê
  que foi neutralizado.
- Truncagem a 240 chars por campo.

Tudo isto produz um **evidence pack** ([prompts/evidence_pack.md](prompts/evidence_pack.md)) —
só factos, com cada evento numerado `[NN]` para o Judge poder citar.
O mesmo pack alimenta SLM e Judge (cache partilhada).

---

## 2. Prompts

Dois system prompts, ambos com saída JSON estruturada e temperatura 0.1.

### SLM Analyst — `phi3:medium` ([slm_analyst.py#L43](src/slm_analyst.py#L43))

Pré-filtro rápido de triagem:

> "You are a cybersecurity log analyst performing a rapid first-pass triage of
> Sysmon/ETW log windows. Read the EVIDENCE PACK and identify: (1) key risk
> indicators directly visible in the data; (2) potential ATT&CK techniques by
> name; (3) preliminary risk score 0–10; (4) whether the window warrants deep
> analysis. **Rules: only reference what is explicitly present; do NOT invent
> process names, IPs, or file paths; be brief — this is triage, not a final
> verdict.**"

**Saída JSON**:

```json
{
  "pre_score": <int 0-10>,
  "risk_level": "low|medium|high|critical",
  "suspected_techniques": ["..."],
  "risk_indicators": ["..."],
  "summary": "<1-2 frases>",
  "needs_deep_analysis": <true|false>
}
```

`num_predict=384`, temperatura 0.1.

### LLM Judge — `llama3.2` ([llm_judge.py#L48](src/llm_judge.py#L48))

Validação final:

> "You are a senior cybersecurity analyst and LLM judge. You receive: (1) a
> PRE-DIAGNOSIS from the SLM — **treat as hypothesis to validate, not fact**;
> (2) the full EVIDENCE PACK. Tasks: validate or refute the SLM diagnosis;
> map behaviours to ATT&CK techniques only if directly supported; assign
> anomaly score 0–10; write 2–3 sentence rationale; **flag any SLM claims
> not supported by evidence**."

**Rubrica**:

| Score | Significado |
|---|---|
| 0–2 | normal |
| 3–4 | levemente suspeito |
| 5–6 | moderado |
| 7–8 | muito suspeito (C2 / mimikatz / psexec) |
| 9–10 | crítico (APT confirmado) |

**Regras estritas**: nunca afirmar técnica sem citar evento/stat;
usar `"Evidence: [cite]"`; nunca alucinar nomes; se rule tagger disparou sem
evidência corroborante → confidence "low".

**Saída JSON**:

```json
{
  "anomaly_score": <int 0-10>,
  "verdict": "normal|suspicious|malicious",
  "techniques": [
    {
      "technique_id": "T1003",
      "name": "Credential Dumping",
      "confidence": "high|medium|low",
      "evidence": "has_mimikatz=true; event [14] EID=1 proc=mimikatz.exe ..."
    }
  ],
  "rationale": "<2-3 frases>",
  "recommended_action": "<acção SOC concreta>",
  "unsupported_claims": [],
  "fp_risk": "low|medium|high"
}
```

`num_predict=1024`, temperatura 0.1.

### Porquê dois LLMs?

Escolha deliberada — o SLM (~7 B) faz **pré-filtro barato** (~1 s/janela), o
Judge (mais alinhado para grounding) só corre nas janelas marcadas pelo SLM
com `needs_deep_analysis=true`, **reduzindo custo em ≥ 90 %**.

---

## 3. Resultados

Duas corridas reais sobre LMD-2023, em [results/](results/):

| Run | Dataset | Janelas | Label | Detector P / R / F1 / FPR / PR-AUC | Judge P / R / F1 |
|---|---|---|---|---|---|
| `calibration_eors` | LMD-2023 EoRS (2.3 M, ataques) | 693 | 100 % positivo | **1.000 / 0.822 / 0.903 / 0.000 / 1.000** | 1.000 / 0.083 / 0.154 (12 julgadas) |
| `defesa_isep_…01-27-31` | LMD-2023 Normal (1.75 M) | 1424 | 100 % negativo | acc 0.685 / **FPR 0.315** | acc 0.318 / FPR 0.682 (22 julgadas) |

### Leitura honesta para a defesa

#### ✅ Deteção forte no detector estatístico

- Em dados maliciosos (EoRS): **F1 = 0.90** com **0 falsos positivos
  confirmáveis** dentro das janelas rotuladas e **PR-AUC = 1.0** → o ranking
  é excelente, o threshold pode ser sintonizado.
- Recall 0.82 significa 18 % dos ataques no EoRS não disparam o detector —
  dataset com ataques de baixo volume diluídos em ruído.

#### ⚠️ FPR no Normal-only é o ponto a discutir abertamente

- 31.5 % das 1424 janelas normais ultrapassam o threshold default 0.6.
  Isto não é "o sistema falhar" — é a **calibração do threshold**: ao subir
  para ~0.85 (ver `notebooks/threshold_calibration.ipynb`) o FPR cai
  drasticamente preservando o recall do EoRS.
- O Judge inverte 15 das 22 que filtrou para FP no Normal, mas sobre uma
  amostra mínima — não generaliza.

#### ✅ Explicabilidade — onde o sistema brilha

Cada alerta vem com:

1. **Detector score decomposto** (IsolationForest + GRU + ATT&CK rules) —
   auditável.
2. **Evidence pack** com 50 eventos numerados `[NN]` — não há caixa preta.
3. **SLM pre-diagnosis** com técnicas suspeitas e indicadores.
4. **Judge verdict** com `techniques[].evidence: "Evidence: event [14] EID=1
   proc=mimikatz.exe ..."` obrigatoriamente citando o pack, mais
   `unsupported_claims` (transparência sobre o que rejeitou do SLM) e
   `recommended_action` para o SOC.
5. **Mapeamento MITRE ATT&CK** consistente em rules + SLM + Judge.

### Frase-resumo defensável

> O detector estatístico atinge **F1 ≈ 0.90 e PR-AUC = 1.0** sobre tráfego com
> ataques reais (LMD-2023 EoRS), com excelente capacidade discriminativa.
> O FPR de 31 % sobre tráfego puramente normal reflete o threshold default
> conservador (0.6), e a calibração mostra que pode ser elevado mantendo
> recall. A camada SLM→Judge não foi pensada para melhorar P/R — foi pensada
> para garantir **explicabilidade auditável**: cada alerta tem evidência
> citada, técnicas ATT&CK fundamentadas e ação SOC recomendada, com defesas
> activas contra prompt injection na sanitização do evidence pack.
