# Startup Guide — Challenge 3

Guia completo para instalar e iniciar todos os componentes do projeto.

---

## Pré-requisitos globais

| Ferramenta | Versão mínima | Download |
|---|---|---|
| Python | 3.11 | https://www.python.org/downloads/ |
| Conda (Miniconda/Anaconda) | qualquer | https://docs.conda.io/en/latest/miniconda.html |
| Ollama | qualquer | https://ollama.com/download |
| Git | qualquer | https://git-scm.com/ |
| Câmera web | — | necessária para autenticação facial |

---

## 1. Sistema Principal — Frontend + Cyber Anomaly Detection

> **Recomendado.** Sistema integrado com autenticação facial e dashboard SOC.

### 1.1 Instalar dependências

```bash
# A partir da raiz do projeto (d:\ISEP\Challange-3)
conda env create -f cyber-anomaly-detection/environment.yml
conda activate cyber-anomaly
```

O ambiente `cyber-anomaly` instala automaticamente:
- Python 3.11
- PyTorch com CUDA 12.6
- numpy, pandas, scikit-learn, gensim, sentence-transformers
- chromadb, rank-bm25 (RAG híbrido)
- streamlit, fastapi, flask
- mlflow, optuna, xgboost, lightgbm, catboost
- plotly, matplotlib, seaborn

Instalar também as dependências do frontend (insightface, opencv, etc.):

```bash
conda run -n cyber-anomaly pip install -r requirements.txt
```

O `requirements.txt` raiz instala:
- Flask>=3.0
- opencv-python>=4.8
- insightface>=0.7
- onnxruntime>=1.16
- facenet-pytorch>=0.2.2
- Pillow>=9.0

### 1.2 Configurar o Ollama (atribuição ATT&CK)

```bash
# Terminal separado — manter aberto
ollama serve

# Descarregar modelo (escolher um):
ollama pull qwen2.5:32b     # melhor qualidade (~20 GB VRAM)
ollama pull phi4:14b        # mais leve (~9 GB VRAM)
```

### 1.3 Variáveis de ambiente (opcionais)

```bash
# Windows PowerShell
$env:OLLAMA_BASE_URL = "http://localhost:11434"   # padrão
$env:OLLAMA_MODEL    = "qwen2.5:32b"              # padrão
$env:OLLAMA_TIMEOUT  = "600"                       # segundos
$env:FRONTEND_DEBUG  = "1"                         # ativar debug Flask
$env:WORKSPACE_ROOT  = "d:\ISEP\Challange-3"      # raiz dos datasets
```

> **Importante:** `config.py` aponta por padrão para `h:\Challenge-3-4`. Se os datasets
> estiverem noutro local, define `WORKSPACE_ROOT` antes de arrancar.

### 1.4 Iniciar a aplicação

```bash
conda run -n cyber-anomaly python frontend/app.py
```

Abrir no browser: **http://localhost:5000**

**Fluxo de utilização:**
1. Conceder acesso à câmera e clicar **Authenticate**
2. O sistema captura vários frames e compara com os rostos em `frontend/pessoas_permitidas/`
3. Se a similaridade coseno ≥ 0.70, redireciona para o **SOC Dashboard**
4. No dashboard: selecionar uma chain suspeita → ver scores → correr atribuição ATT&CK

**Utilizadores registados:** Arsénio, César, Gonçalo, Rui Soares, Rynalde
(imagens em `frontend/pessoas_permitidas/<nome>/`)

---

## 2. Demo Streamlit Standalone (Cyber Anomaly Detection)

> Explorar o pipeline de deteção sem o frontend de autenticação.

### 2.1 Instalar dependências

Mesmo ambiente do sistema principal (passo 1.1).

### 2.2 Iniciar

```bash
conda activate cyber-anomaly
cd cyber-anomaly-detection
streamlit run demo_app.py
```

Abrir no browser: **http://localhost:8501**

---

## 3. DualSentinel (abordagem alternativa)

> Pipeline mais leve: IsolationForest + GRU + Phi-3 + Llama 3.1.

### 3.1 Instalar dependências

```bash
cd DualSentinel
python -m venv .venv

# Windows
.venv\Scripts\activate

pip install -r requirements.txt
```

O `requirements.txt` instala:
- pandas, numpy, scikit-learn
- torch>=2.1.0
- python-evtx (parse de ficheiros .evtx)
- python-dotenv
- rich, typer (CLI)
- ollama>=0.3.0
- pydantic, tqdm, matplotlib, seaborn

### 3.2 Configurar o Ollama

```bash
# Terminal separado
ollama serve

# Descarregar modelos necessários:
ollama pull phi3:medium    # SLM Analyst (~8 GB)
ollama pull llama3.2:latest       # LLM Judge   (~2 GB, versão 3B)
# ollama pull llama3.2:latest # versão maior se tiveres VRAM suficiente
```

### 3.3 Configurar variáveis de ambiente

```bash
# Ainda dentro de DualSentinel/
copy .env.example .env
# Editar .env com um editor de texto
```

Conteúdo do `.env`:
```
ANTHROPIC_API_KEY=sk-ant-your-key-here   # só se usar Claude em vez de Ollama local
JUDGE_MODEL=claude-sonnet-4-6
ANOMALY_THRESHOLD=0.6
WINDOW_SIZE_SECONDS=60
MAX_EVENTS_PER_WINDOW=200
OLLAMA_BASE_URL=http://localhost:11434
USE_LOCAL_SLM=false
LOG_LEVEL=INFO
```

### 3.4 Iniciar o pipeline

```bash
# Pipeline completo (IsolationForest + GRU + SLM Analyst + LLM Judge)
python src/pipeline.py --input data/samples/sample_lmd.csv --dataset lmd

# Saltar o passo LLM (só detectores clássicos)
python src/pipeline.py --input data/samples/sample_lmd.csv --dataset lmd --skip-judge

# Só detectores, sem SLM/LLM
python src/pipeline.py --input data/samples/sample_lmd.csv --dataset lmd --skip-detectors --threshold 0.2

# Avaliação com métricas
python src/pipeline.py --input data/samples/sample_lmd.csv --dataset lmd --evaluate
```

Resultados em: `DualSentinel/results/YYYY-MM-DD_HH-MM/`

---

## 4. RNAAPIA — Reconhecimento Facial (alternativa standalone)

> Alternativa escalável de reconhecimento facial com InsightFace + câmera ao vivo.

### 4.1 Instalar dependências

```bash
cd "RNAAPIA/Alternativa Escalavel"
python -m venv .venv
.venv\Scripts\activate

pip install insightface onnxruntime opencv-python numpy scikit-learn
# Para GPU:
# pip install onnxruntime-gpu
```

### 4.2 Preparar base de dados de rostos

Colocar fotos (JPEG/PNG) em:
```
RNAAPIA/Alternativa Escalavel/pessoas_permitidas/<Nome>/foto1.jpg
```

### 4.3 Iniciar

```bash
python main.py
```

---

## 5. RNAAPIA — Fine Tuning (notebooks e demos)

> Modelos CNN/ResNet treinados para reconhecimento facial.

### 5.1 Instalar dependências

```bash
conda activate cyber-anomaly   # reutilizar o ambiente principal
# ou criar um novo:
pip install torch torchvision facenet-pytorch Pillow scikit-learn matplotlib
```

### 5.2 Opções de execução

```bash
# Demo CNN
python "RNAAPIA/Fine Tuning/demo_faceCNN_classificacao.py"

# Demo ResNet
python "RNAAPIA/Fine Tuning/demo_resnet_classificacao.py"

# Notebooks (abrir com JupyterLab)
conda run -n cyber-anomaly jupyter lab
# Navegar para RNAAPIA/Notebooks Jupyter/ ou RNAAPIA/Fine Tuning/
```

---

## Resumo de portas e serviços

| Serviço | Porta | Comando de arranque |
|---|---|---|
| Frontend Flask (sistema principal) | 5000 | `conda run -n cyber-anomaly python frontend/app.py` |
| Streamlit demo | 8501 | `streamlit run demo_app.py` |
| Ollama | 11434 | `ollama serve` |
| JupyterLab | 8888 | `conda run -n cyber-anomaly jupyter lab` |

---

## Ordem recomendada de arranque (sistema principal)

```
1. ollama serve                                         (terminal 1 — manter aberto)
2. ollama pull qwen2.5:32b  (ou phi4:14b)               (esperar download)
3. conda activate cyber-anomaly
4. conda run -n cyber-anomaly pip install -r requirements.txt
5. conda run -n cyber-anomaly python frontend/app.py    (terminal 2)
6. Abrir http://localhost:5000
```
