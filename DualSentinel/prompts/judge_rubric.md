# LLM Judge Rubric

Rubrica usada no system prompt de `llm_judge.py`.

## Scoring

| Score | Significado |
|---|---|
| 0–2 | Normal / benigno |
| 3–4 | Levemente suspeito (entropia elevada, contagens incomuns) |
| 5–6 | Moderadamente suspeito (processos suspeitos, indicadores LM) |
| 7–8 | Muito suspeito (C2, mimikatz, psexec, padrões ransomware) |
| 9–10 | Crítico (TTPs APT confirmadas com múltiplos pontos corroborados) |

## Regras de grounding anti-alucinação

1. **Nunca** afirmar uma técnica sem citar evento específico ou stat do evidence pack
2. Se o rule tagger assinalou um hit mas não há eventos corroborantes → confidence "low"
3. **Nunca** inventar nomes de processos, IPs ou ficheiros não presentes no pack
4. Usar sempre `"Evidence: [citar]"` para cada técnica

## Output JSON esperado

```json
{
  "anomaly_score": 8,
  "verdict": "malicious",
  "techniques": [
    {
      "technique_id": "T1003",
      "name": "Credential Dumping",
      "confidence": "high",
      "evidence": "has_mimikatz=true; event [14] EID=1 proc=mimikatz.exe cmd=sekurlsa::logonpasswords"
    }
  ],
  "rationale": "Window shows lateral movement via SMB (events [04],[05]) followed by credential dumping (mimikatz, event [14]) and persistence via scheduled task (event [16]).",
  "unsupported_claims": [],
  "fp_risk": "low"
}
```

## fp_risk guidelines

- **low**: evidência direta no pack, combinação de técnicas coerente
- **medium**: indicadores ambíguos (ex: net.exe pode ser admin legítimo)
- **high**: apenas rule tagger hit sem eventos corroborantes
