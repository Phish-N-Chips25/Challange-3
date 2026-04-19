# Porquê manter a 1ª Sentinela (Heuristic Scorer)

> Resposta à pergunta: *"faz sentido remover a 1ª sentinela — deteção heurística — e passar direto para a 2ª sentinela?"*

Não, não faz sentido — e na prática ia partir o projeto. Razões concretas:

## 1. Custo / latência de inferência

O LMD-2023 tem ~1.75M eventos → ~30k janelas de 60s. Llama 3.1 + Phi-3 via Ollama demoram **5-15s por janela** (pré-fill da evidence pack + geração JSON). Sem gating:

- 30k janelas × 10s ≈ **83 horas** de GPU para um único ficheiro
- Com o filtro heurístico (~95% das janelas são "trivially benign" no LMD): cai para ~1500 janelas → **~4h**

O scorer heurístico é o que torna o pipeline executável em hardware académico.

## 2. Sinal vs ruído para o LLM

Quase todas as janelas são benignas (tráfego normal de Windows). Se mandares todas ao LLM:

- O Judge passa 95% do tempo a confirmar "normal", o que **ancora o prior dele para baixo** e aumenta falsos negativos quando aparece algo suspeito.
- Os modelos pequenos (Phi-3 Medium) **alucinam mais** quando recebem entrada sem sinal — inventam técnicas ATT&CK em janelas vazias só porque o prompt pede JSON com `suspected_techniques`.

O scorer heurístico funciona como um **filtro de relevância**: o LLM só vê janelas onde *algo* (regra, KB, smart feature, ou desvio do baseline) já levantou suspeita.

## 3. Auditabilidade e falseabilidade

Sem o scorer, não tens forma determinística de responder a "porquê é que esta janela foi analisada?". O score 0-1 com termos inspecionáveis (regra X, KB hit Y, baseline deviation Z) é o que torna o sistema **defensável academicamente** — a parte LLM por si só é uma caixa preta.

## 4. Perdes a contribuição self-supervised

A `BenignBaseline` (centroid + token rarity) é a única parte do pipeline que aprende dos dados sem labels. Se removeres o scorer, ela deixa de ter consumidor — e é precisamente um dos requisitos académicos que tinhas (sinais semânticos para além de regras).

## 5. Sem fallback se o Ollama falhar

Se o Ollama crashar, a 1ª sentinela ainda produz `windows_scored.json` com scores e ATT&CK hits — operacionalmente útil. Sem ela, uma falha de LLM = pipeline sem output.

## Quando faria sentido

- **Em produção SOC com janelas muito raras** (e.g. só alertas já triados por SIEM a montante), aí sim podes mandar tudo ao LLM porque o volume já está pré-filtrado.
- **Para um demo de 50 janelas** podes desligar o threshold (`--threshold 0`) e mandar tudo ao LLM — útil para debug, mas não é o modo normal.

## Reformulação possível (se a ideia é simplificar a narrativa)

Em vez de remover, podes **reposicionar** o discurso na apresentação:

- "1ª sentinela" deixa de ser apresentada como *detetor* e passa a **gating layer + signal extractor** (extrai sinais que vão para o evidence pack do LLM).
- "2ª sentinela" continua a ser quem decide.

Isto reflete o que o código já faz, evita a impressão de "duas sentinelas a votarem" (que confunde), e mantém todas as vantagens acima.
