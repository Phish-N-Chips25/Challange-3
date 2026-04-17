# Challange-3
Repositório oficial do Challenge 3.

## Frontend de autenticação

Foi adicionada uma interface web simples e direta para autenticação por câmara.

### Como executar

```powershell
pip install -r requirements.txt
python frontend/app.py
```

Por defeito, o frontend arranca sem o reloader do Flask para abrir mais depressa. Se quiseres debug local, define `FRONTEND_DEBUG=1` e, se precisares mesmo, `FRONTEND_RELOADER=1`.

### Estrutura principal

- `frontend/app.py` — interface web principal
- `frontend/servico_autenticacao.py` — camada intermédia que escolhe a alternativa
- `frontend/alt1.py` — validador atual
- `frontend/ui_registry.py` — metadados de interface para as alternativas

### Experiência de autenticação

- O frontend tem agora um visual mais moderno, com efeitos suaves e feedback visual em tempo real.
- A autenticação passa a ser progressiva: a pessoa só é aceite se se mantiver acima do threshold durante alguns segundos seguidos.
- A barra de progresso mostra o tempo acumulado acima do threshold antes de redirecionar para a sessão.

### Fluxo

1. O utilizador abre o site.
2. A câmara aparece logo na página, em quadrado.
3. Clica em **Autenticar**.
4. O frontend captura vários frames em sequência e envia-os ao serviço intermédio.
5. Se o score se mantiver acima do threshold durante o tempo definido, o utilizador passa.
