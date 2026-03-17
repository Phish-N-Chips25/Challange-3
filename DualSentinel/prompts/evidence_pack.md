# Evidence Pack Template

Este ficheiro documenta a estrutura do evidence pack enviado ao LLM judge.
O pack é construído automaticamente por `llm_judge.py::build_evidence_pack()`.

## Estrutura

```
=== EVIDENCE PACK ===
Window: <ISO timestamp> → <ISO timestamp>
Total events: <N>

--- Aggregate stats ---
Unique EventIDs: <N>
Unique processes: <N>
Unique users: <N>
Process creations (EID 1): <N>
Network connections (EID 3): <N>
File creations (EID 11): <N>
Registry modifications (EID 13): <N>
Suspicious processes detected: <N>
Lateral movement ports seen: <N>
PowerShell executions: <N>
CMD executions: <N>
Outbound unique IPs: <N>
Mimikatz present: <bool>
PsExec present: <bool>
EventID entropy: <float>
Process entropy: <float>

--- Rule tagger hits (pre-computed) ---
  T1059.001 PowerShell (confidence=0.70)
  ...

--- Individual event samples (max 50) ---
  [01] EID=1 | proc=powershell.exe | cmd=powershell.exe -NoP -Exec Bypass ...
  [02] EID=3 | proc=powershell.exe | dst=192.168.1.100:80
  ...
```

## Princípios

1. **Só factos**: o pack não contém inferências — é o judge que infere
2. **Referenciável**: cada evento tem número `[NN]` para o judge citar na evidência
3. **Limitado**: máximo 50 eventos para não exceder context window
4. **Truncado**: command lines truncadas a 120 chars para evitar injection
