# Challange-3
Repositório oficial do Challenge 3.

## Frontend de autenticação

Foi adicionada uma interface web simples e direta para autenticação por câmara.

### Como executar

```powershell
pip install -r requirements.txt
python frontend/app.py
```

### Estrutura principal

- `frontend/app.py` — interface web principal
- `frontend/servico_autenticacao.py` — camada intermédia que escolhe a alternativa
- `frontend/alt1.py` — validador atual
- `frontend/ui_registry.py` — metadados de interface para as alternativas

### Fluxo

1. O utilizador abre o site.
2. A câmara aparece logo na página, em quadrado.
3. Clica em **Autenticar**.
4. O frontend captura o frame atual e envia ao serviço intermédio.
5. O serviço devolve `True` ou `False`.
